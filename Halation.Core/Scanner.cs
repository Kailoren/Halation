using System.Diagnostics;
using System.Reflection;

using Halation.Core.Artifacts;
using Halation.Core.Dependencies;
using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Rules;
using Halation.Core.Scoring;

namespace Halation.Core;

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
        // is scored. See Finding.IsCapability and DeclaredPurpose.
        var (findings, capabilities) = PurposeSplit.Apply(
            [.. observed, .. OverDeclaration(observed, options.DeclaredPurpose)],
            options.DeclaredPurpose);

        var coverage = MergeCoverage(
            recovery.Coverage, analysis, dependencies, lookup, deepPass, redundancy)
            with { MinifiedPercent = MinifiedShareOf(recovery.Files) };

        var report = new ScanReport
        {
            ArtifactName = artifact.Name,
            Kind = artifact.Kind,
            ArtifactBytes = artifact.Bytes,
            Sha256 = sha256,

            // A directory has no single stream to hash, so its value is a digest of names and
            // sizes and cannot speak for the contents. Only a file's hash can.
            HashCoversContent = !artifact.IsDirectory,

            ScannedAt = DateTimeOffset.Now,

            // Coverage gates the verdict: without it, an artifact that yielded no readable
            // code at all scores full marks for the absence of findings never looked for.
            Verdict = ScoreCalculator.Calculate(
                findings, coverage.Percent, options.Audience, capabilities),
            Coverage = coverage,
            Findings = findings,
            Capabilities = capabilities,
            Purpose = options.DeclaredPurpose,
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
                ManifestsUnresolved = dependencies.Unresolved.Count,
            },
            Checks = new CheckSummary { Checks = analysis.Checks },
            DeepPassRan = options.DeepPassEnabled,

            // BilledCost, not EstimatedCost. A subscription-backed pass has a real token cost
            // and a bill of nothing; reporting the former as the latter would tell somebody
            // their card was charged when it was not.
            DeepPassCost = deepPass.Backend is not null ? deepPass.BilledCost : null,

            // Always available where a cost may not be, so a pass answered by an endpoint
            // nobody can price still says what it consumed.
            DeepPassTokens = deepPass.Backend is null
                ? null
                : deepPass.Usage.TotalInput + deepPass.Usage.Output,
            DeepPassBackend = deepPass.Backend,
            SourceExplanations = deepPass.Explains,
            ScannerVersion = Version,
            Environment = options.Environment,
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
            Verdict = ScoreCalculator.Calculate(
                report.Findings, report.Coverage.Percent, audience, report.Capabilities),
            CategoryScores = ScoreCalculator.CategoryScores(report.Findings),
        };
    }

    /// <summary>
    /// Re-answers an existing report against a different statement of purpose, without
    /// rescanning.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing about the artifact is examined again. Every finding already names the capability
    /// it demonstrates, so accounting for one is a re-sort of what is already in hand: the same
    /// arithmetic that lets the reader be switched, applied to a different question. That
    /// matters beyond tidiness, because it means answering costs nothing and the two views
    /// cannot disagree about what was found, only about what accounts for it.
    /// </para>
    /// <para>
    /// The declaration check is rebuilt rather than carried over, since it describes the
    /// declaration being replaced.
    /// </para>
    /// </remarks>
    public static ScanReport Reconsider(ScanReport report, DeclaredPurpose? purpose)
    {
        ArgumentNullException.ThrowIfNull(report);

        var observed = report.Findings
            .Concat(report.Capabilities)
            .Where(f => f.RuleId != OverDeclarationRule)
            .ToList();

        var (findings, capabilities) = PurposeSplit.Apply(
            [.. observed, .. OverDeclaration(observed, purpose)],
            purpose);

        return report with
        {
            Verdict = ScoreCalculator.Calculate(
                findings, report.Coverage.Percent, report.Audience, capabilities),
            Findings = findings,
            Capabilities = capabilities,
            CategoryScores = ScoreCalculator.CategoryScores(findings),
            Purpose = purpose,
        };
    }

    /// <summary>
    /// Capabilities in this report that a statement of purpose could account for, so a caller
    /// knows which questions are worth asking and asks no others.
    /// </summary>
    public static IReadOnlyList<Capability> QuestionsFor(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        return [.. report.Findings
            .Where(f => f.IsBlocking && f.Capability is not null)
            .Select(f => f.Capability!.Value)
            .Distinct()];
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
    /// Identifier of the finding raised when a declaration accounts for too much to be worth
    /// anything.
    /// </summary>
    public const string OverDeclarationRule = "VC-PUR-001";

    /// <summary>
    /// How many blocking capabilities a declaration may account for before the declaration is
    /// itself the thing worth reporting.
    /// </summary>
    /// <remarks>
    /// Three. One is an application doing its job; two is a plausible combination, as a
    /// security tool touching both browser stores would be; from three the declaration has
    /// stopped narrowing anything and is just a list of everything that would otherwise have
    /// been said.
    /// </remarks>
    public const int TooMuchAccountedFor = 3;

    /// <summary>
    /// The check on the declaration itself, which no declaration can account for.
    /// </summary>
    /// <remarks>
    /// Affirming a purpose moves findings out of the score, so the obvious way to abuse it is
    /// to affirm everything. That cannot be prevented, and pretending otherwise would be worse
    /// than saying it plainly: this reports the breadth of what was waved through, in the same
    /// report, where anybody reading a screenshot of it can see the same thing the person who
    /// ran the scan saw.
    /// </remarks>
    private static IEnumerable<Finding> OverDeclaration(
        IReadOnlyList<Finding> observed,
        DeclaredPurpose? purpose)
    {
        if (purpose is null)
        {
            yield break;
        }

        var waved = observed
            .Where(f => f.IsBlocking
                        && f.Capability is { } capability
                        && purpose.Accounts(capability))
            .Select(f => f.Capability!.Value)
            .Distinct()
            .ToList();

        if (waved.Count < TooMuchAccountedFor)
        {
            yield break;
        }

        var listed = string.Join(", ", waved.Select(c => c.Humanise().ToLowerInvariant()));

        yield return new Finding
        {
            RuleId = OverDeclarationRule,
            Title = "This application was said to have a reason for most of what was found",
            Severity = Severity.Medium,
            UserSeverity = Severity.Medium,
            Category = FindingCategory.CodeSafety,
            Description =
                $"{waved.Count} separate behaviours that would each advise against installing "
                + $"this application were accounted for as intended: {listed}. A statement of "
                + "purpose that covers nearly everything found narrows nothing, and the quiet "
                + "result below rests entirely on it being true.",
            Remediation =
                "If these really are all intended, nothing here needs fixing and this finding "
                + "is the report being honest about how much it was asked to take on trust.",
            UserDescription =
                $"This application does {waved.Count} separate things that would normally be "
                + $"reason enough not to install it: {listed}. All of them were marked as "
                + "expected. If you were not certain about every one of those, the result above "
                + "is friendlier than what was actually found.",
            UserRemediation =
                "Go back and account only for what you specifically know this application is "
                + "for, then read the result again.",
        };
    }

    /// <summary>
    /// How much of the recovered code arrived as a bundle rather than as readable text.
    /// </summary>
    /// <remarks>
    /// By bytes rather than by file count, because one bundle and forty small configuration
    /// files is not 2% minified in any sense a reader cares about. Computed here rather than in
    /// each backend so every artifact kind answers the question the same way.
    /// </remarks>
    private static int MinifiedShareOf(IReadOnlyList<RecoveredFile> files)
    {
        long total = 0;
        long minified = 0;

        foreach (var file in files)
        {
            total += file.Content.Length;

            if (file.IsMinified)
            {
                minified += file.Content.Length;
            }
        }

        return total == 0 ? 0 : (int)Math.Round(minified / (double)total * 100);
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
