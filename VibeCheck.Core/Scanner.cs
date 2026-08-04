using System.Diagnostics;
using System.Reflection;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Core;

/// <summary>Stage the scan has reached, for progress reporting in the UI.</summary>
public enum ScanStage
{
    Identifying,
    Recovering,
    Analysing,
    CheckingDependencies,

    /// <summary>
    /// The optional reasoning pass. Its own stage rather than more of <see cref="Analysing"/>,
    /// because it counts through its own files from zero: sharing a stage made the progress
    /// bar rewind to the middle of the scan every time the deep pass started.
    /// </summary>
    DeepPass,
    Scoring,
    Complete,
}

public sealed record ScanProgress(ScanStage Stage, string Message, int? Percent = null);

/// <summary>
/// Runs a complete scan: identify the artifact, recover what source it has, apply the rule
/// catalog, check its dependencies, and score the result.
/// </summary>
/// <remarks>
/// Two steps can touch the network and both are opt-out or opt-in: the dependency check,
/// which sends package names and versions only, and the deep pass, which is off unless asked
/// for. Everything else is local, including all recovery and every rule.
/// </remarks>
public sealed class Scanner
{
    private readonly IReadOnlyList<IRecoveryBackend> _backends;
    private readonly RuleEngine _rules;

    public Scanner(IEnumerable<IRecoveryBackend>? backends = null, RuleEngine? rules = null)
    {
        _backends = backends?.ToList() ??
        [
            new DotNetRecoveryBackend(),
            new SingleFileRecoveryBackend(),
            new ElectronRecoveryBackend(),
            new InstallerRecoveryBackend(),
            new SourceRecoveryBackend(),
            new NativeRecoveryBackend(),
        ];

        _rules = rules ?? new RuleEngine();
    }

    public Task<ScanReport> ScanAsync(
        string path,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        ScanAsync(path, ScanOptions.Default, progress, cancellationToken);

    public async Task<ScanReport> ScanAsync(
        string path,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(options);

        var stopwatch = Stopwatch.StartNew();

        progress?.Report(new ScanProgress(ScanStage.Identifying, "Identifying artifact"));
        var artifact = ArtifactDetector.Detect(path);
        var sha256 = ArtifactDetector.ComputeSha256(artifact);

        progress?.Report(new ScanProgress(
            ScanStage.Recovering,
            $"Recovering source from {artifact.Name}"));

        var backend = _backends.FirstOrDefault(b => b.CanHandle(artifact.Kind))
                      ?? new NativeRecoveryBackend();

        var recovery = await backend.RecoverAsync(artifact, cancellationToken).ConfigureAwait(false);

        progress?.Report(new ScanProgress(
            ScanStage.Analysing,
            $"Analysing {recovery.Files.Count:N0} files",
            0));

        var ruleProgress = recovery.Files.Count == 0
            ? null
            : new Progress<int>(done => progress?.Report(new ScanProgress(
                ScanStage.Analysing,
                $"Analysing {recovery.Files.Count:N0} files",
                (int)(done / (double)recovery.Files.Count * 100))));

        var analysis = _rules.Analyse(recovery.Files, ruleProgress, cancellationToken);

        progress?.Report(new ScanProgress(ScanStage.CheckingDependencies, "Checking dependencies"));

        var dependencies = DependencyInventory.Extract(recovery.Files);
        var lookup = await CheckDependenciesAsync(dependencies, options, cancellationToken)
            .ConfigureAwait(false);

        // The optional reasoning pass, after the deterministic one so it can be told what has
        // already been found and triage against it rather than duplicating it.
        var deepPass = await DeepPass.DeepPassRunner.RunAsync(
            recovery.Files,
            [.. PackagingChecks.Run(artifact).Concat(recovery.Findings).Concat(analysis.Findings)],
            options,
            progress: progress,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        progress?.Report(new ScanProgress(ScanStage.Scoring, "Scoring results"));

        // Repetition and dead weight, over verbatim source only. Informational throughout: it
        // is a maintenance cost rather than a risk, and it must not move a number that answers
        // how dangerous something is.
        var redundancy = Quality.RedundancyChecks.Run(recovery.Files);

        // Five stages contribute findings and all are equally real, they were just observed
        // at different depths: packaging looks at which files ship, recovery at the binary,
        // the rule pass at recovered source, the dependency check at published advisories, and
        // the redundancy pass at how much of the source repeats itself.
        var observed = PackagingChecks.Run(artifact)
            .Concat(recovery.Findings)
            .Concat(analysis.Findings)
            .Concat(VulnerabilityFindings.Build(lookup))
            .Concat(deepPass.Findings)
            .Concat(redundancy.Findings)

            // Ordered by what matters to whoever is reading. Sorting an end user's report by
            // the developer's severity would open it with a leaked key they cannot act on and
            // bury the thing that actually reaches their machine.
            .OrderByDescending(f => f.SeverityFor(options.Audience))
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();

        // Split here, once, so that nothing downstream has to remember to exclude capabilities
        // from the arithmetic. What an application can do is reported; only what it does wrong
        // is scored. See Finding.IsCapability.
        var capabilities = observed.Where(f => f.IsCapability).ToList();
        var findings = observed.Where(f => !f.IsCapability).ToList();

        var coverage = MergeCoverage(
            recovery.Coverage, analysis, dependencies, lookup, deepPass, redundancy);

        var report = new ScanReport
        {
            ArtifactName = artifact.Name,
            Kind = artifact.Kind,
            ArtifactBytes = artifact.Bytes,
            Sha256 = sha256,
            ScannedAt = DateTimeOffset.Now,

            // Coverage gates the verdict: without it, an artifact that yielded no readable
            // code at all scores full marks for the absence of findings never looked for.
            Verdict = ScoreCalculator.Calculate(findings, coverage.Percent, options.Audience),
            Coverage = coverage,
            Findings = findings,
            Capabilities = capabilities,
            CategoryScores = ScoreCalculator.CategoryScores(findings),
            VulnerabilityData = lookup.Provenance,
            Effort = new ScanEffort
            {
                RecoveryMethod = ScanEffort.MethodFor(artifact.Kind),
                FilesRecovered = coverage.RecoveredFileCount,
                BytesRecovered = coverage.RecoveredBytes,
                ChecksRun = _rules.Rules.Count,
                FilesChecked = analysis.FilesAnalysed,
                PackagesResolved = dependencies.Dependencies.Count,

                // Resolved and checked differ whenever the lookup declined:
                // no bundle, no network, or the check switched off. Reporting the resolved
                // count as though it had been checked would claim work that did not happen.
                PackagesChecked = lookup.Provenance.Origin == VulnerabilityDataOrigin.None
                    ? 0
                    : dependencies.Dependencies.Count,
                VulnerabilityData = lookup.Provenance,
                MatchesDiscounted = analysis.MatchesDiscounted,
            },
            Checks = new CheckSummary { Checks = analysis.Checks },
            DeepPassRan = options.DeepPassEnabled,

            // BilledCost, not EstimatedCost. A subscription-backed pass has a real token cost
            // and a bill of nothing; reporting the former as the latter would tell somebody
            // their card was charged when it was not.
            DeepPassCost = deepPass.Backend is not null ? deepPass.BilledCost : null,
            DeepPassBackend = deepPass.Backend,
            ScannerVersion = Version,
            Duration = stopwatch.Elapsed,
        };

        progress?.Report(new ScanProgress(ScanStage.Complete, "Scan complete", 100));

        return report;
    }

    /// <summary>
    /// Re-answers an existing report for the other reader, without rescanning.
    /// </summary>
    /// <remarks>
    /// Every finding already carries a severity for both audiences, so switching reader is
    /// arithmetic over what is in hand rather than new work. Nothing about the artifact is
    /// re-examined, which also means the two views can never disagree about what was found,
    /// only about what it means for the person reading.
    /// </remarks>
    public static ScanReport Rescore(ScanReport report, Audience audience)
    {
        ArgumentNullException.ThrowIfNull(report);

        if (report.Verdict.Audience == audience)
        {
            return report;
        }

        return report with
        {
            Verdict = ScoreCalculator.Calculate(report.Findings, report.Coverage.Percent, audience),
            CategoryScores = ScoreCalculator.CategoryScores(report.Findings),
        };
    }

    /// <summary>
    /// Looks the dependencies up against published advisories.
    /// </summary>
    private static async Task<VulnerabilityLookupResult> CheckDependenciesAsync(
        DependencyInventoryResult dependencies,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (!options.CheckDependencies)
        {
            return VulnerabilityLookupResult.Unavailable(
                "Dependency checking was switched off for this scan.");
        }

        var source = options.VulnerabilitySource
                     ?? new LiveVulnerabilitySource(OsvClient.Create());

        return await source.LookupAsync(dependencies.Dependencies, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Folds everything that did not actually run into the coverage report.
    /// </summary>
    /// <remarks>
    /// A check that timed out, a dependency whose version could not be resolved, or a whole
    /// category with no data behind it must never read as a check that found nothing.
    /// </remarks>
    private static CoverageReport MergeCoverage(
        CoverageReport coverage,
        RuleEngineResult analysis,
        DependencyInventoryResult dependencies,
        VulnerabilityLookupResult lookup,
        DeepPass.DeepPassResult deepPass,
        Quality.RedundancyResult redundancy)
    {
        var limitations = new List<string>(coverage.ChecksNotPossible);

        limitations.AddRange(analysis.Limitations);
        limitations.AddRange(dependencies.Notes);
        limitations.AddRange(lookup.Notes);
        limitations.AddRange(lookup.NotChecked.Take(20));

        // Which files the deep pass read, and that its findings are inferred. A pass that
        // examined twelve files has not cleared the rest.
        limitations.AddRange(deepPass.Limitations);

        // Which files the duplication check compared, and which it refused to. Silence here
        // would let a scan of a decompiled binary read as one that found no repetition, when
        // in fact it declined to look.
        limitations.AddRange(redundancy.Limitations);

        if (dependencies.Unresolved.Count > 0)
        {
            limitations.Add(
                $"{dependencies.Unresolved.Count} manifest(s) declared only version ranges with "
                + "no lock file, so those dependencies could not be checked: "
                + string.Join(", ", dependencies.Unresolved.Take(5)));
        }

        return limitations.Count == coverage.ChecksNotPossible.Count
            ? coverage
            : coverage with { ChecksNotPossible = limitations };
    }

    /// <summary>
    /// The build's own version, stamped into every report.
    /// </summary>
    /// <remarks>
    /// Read from the informational version rather than the assembly version, because that is
    /// the only one that carries a prerelease suffix: an assembly version is four numbers and
    /// cannot say "beta". A report from a beta build should say which build produced it, and
    /// the numeric version alone would have every prerelease claiming to be the release. The
    /// build metadata after a "+" is dropped, being a commit hash nobody reading a report needs.
    /// </remarks>
    public static string Version =>
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            is { Length: > 0 } informational
            ? informational.Split('+')[0]
            : Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
}
