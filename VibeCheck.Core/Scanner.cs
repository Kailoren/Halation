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
    Scoring,
    Complete,
}

public sealed record ScanProgress(ScanStage Stage, string Message, int? Percent = null);

/// <summary>
/// Runs a complete scan: identify the artifact, recover what source it has, apply the rule
/// catalog, check its dependencies, and score the result.
/// </summary>
/// <remarks>
/// The only step that can touch the network is the dependency check, and only when the
/// options allow it. Everything else is local, so an isolated scan is a scan with that one
/// step pointed at an offline source.
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
        var lookup = await CheckDependenciesAsync(dependencies, options, artifact, cancellationToken)
            .ConfigureAwait(false);

        var bundlePath = WriteBundleIfRequested(options, artifact, sha256, dependencies, lookup);

        progress?.Report(new ScanProgress(ScanStage.Scoring, "Scoring results"));

        // Four stages contribute findings and all are equally real, they were just observed
        // at different depths: packaging looks at which files ship, recovery at the binary,
        // the rule pass at recovered source, and the dependency check at published advisories.
        var findings = PackagingChecks.Run(artifact)
            .Concat(recovery.Findings)
            .Concat(analysis.Findings)
            .Concat(VulnerabilityFindings.Build(lookup))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();

        var coverage = MergeCoverage(recovery.Coverage, analysis, dependencies, lookup);

        var report = new ScanReport
        {
            ArtifactName = artifact.Name,
            Kind = artifact.Kind,
            ArtifactBytes = artifact.Bytes,
            Sha256 = sha256,
            ScannedAt = DateTimeOffset.Now,

            // Coverage gates the verdict: without it, an artifact that yielded no readable
            // code at all scores full marks for the absence of findings never looked for.
            Verdict = ScoreCalculator.Calculate(findings, coverage.Percent),
            Coverage = coverage,
            Findings = findings,
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

                // Resolved and checked differ whenever the lookup declined: isolate mode with
                // no bundle, no network, or the check switched off. Reporting the resolved
                // count as though it had been checked would claim work that did not happen.
                PackagesChecked = lookup.Provenance.Origin == VulnerabilityDataOrigin.None
                    ? 0
                    : dependencies.Dependencies.Count,
                VulnerabilityData = lookup.Provenance,
            },
            BundlePath = bundlePath,
            RanIsolated = options.Isolate,
            ScannerVersion = Version,
            Duration = stopwatch.Elapsed,
        };

        progress?.Report(new ScanProgress(ScanStage.Complete, "Scan complete", 100));

        return report;
    }

    /// <summary>
    /// Selects the vulnerability tier and runs it.
    /// </summary>
    /// <remarks>
    /// Isolate mode never constructs a network-backed source, so the guarantee is structural
    /// rather than a condition checked at the point of use.
    /// </remarks>
    private static async Task<VulnerabilityLookupResult> CheckDependenciesAsync(
        DependencyInventoryResult dependencies,
        ScanOptions options,
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken)
    {
        if (!options.CheckDependencies)
        {
            return VulnerabilityLookupResult.Unavailable(
                "Dependency checking was switched off for this scan.");
        }

        var source = SelectSource(options, artifact);

        if (options.Isolate && source.RequiresNetwork)
        {
            throw new InvalidOperationException(
                "An isolated scan must not use a network-backed vulnerability source.");
        }

        return await source.LookupAsync(dependencies.Dependencies, cancellationToken)
            .ConfigureAwait(false);
    }

    private static IVulnerabilitySource SelectSource(ScanOptions options, ArtifactDescriptor artifact)
    {
        if (options.VulnerabilitySource is { } supplied)
        {
            return supplied;
        }

        if (!options.Isolate)
        {
            return new LiveVulnerabilitySource(OsvClient.Create());
        }

        var bundlePath = options.BundlePath ?? DefaultBundlePath(artifact);

        if (bundlePath is not null && ScanBundle.Load(bundlePath) is { } bundle)
        {
            return new ScanBundleVulnerabilitySource(bundle, ArtifactDetector.ComputeSha256(artifact));
        }

        return new NoVulnerabilitySource(
            "This scan ran isolated with no offline data bundle available, so dependencies "
            + "were not checked. Run a normal scan first to produce a bundle, then bring it "
            + "here alongside the artifact.");
    }

    /// <summary>
    /// Writes the offline bundle beside the artifact, never inside it.
    /// </summary>
    /// <remarks>
    /// Writing into a scanned folder would modify the very thing under examination, which is
    /// unacceptable when the artifact may be evidence.
    /// </remarks>
    private static string? WriteBundleIfRequested(
        ScanOptions options,
        ArtifactDescriptor artifact,
        string sha256,
        DependencyInventoryResult dependencies,
        VulnerabilityLookupResult lookup)
    {
        if (!options.WriteBundle
            || options.Isolate
            || lookup.Provenance.Origin != VulnerabilityDataOrigin.Live)
        {
            return null;
        }

        var directory = options.BundleDirectory ?? Path.GetDirectoryName(artifact.Path.TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        var target = Path.Combine(directory, ScanBundle.FileNameFor(artifact.Name));

        try
        {
            ScanBundle
                .From(artifact.Name, sha256, dependencies.Dependencies, lookup)
                .Save(target);

            return target;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? DefaultBundlePath(ArtifactDescriptor artifact)
    {
        var directory = Path.GetDirectoryName(artifact.Path.TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        return string.IsNullOrEmpty(directory)
            ? null
            : Path.Combine(directory, ScanBundle.FileNameFor(artifact.Name));
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
        VulnerabilityLookupResult lookup)
    {
        var limitations = new List<string>(coverage.ChecksNotPossible);

        limitations.AddRange(analysis.Limitations);
        limitations.AddRange(dependencies.Notes);
        limitations.AddRange(lookup.Notes);
        limitations.AddRange(lookup.NotChecked.Take(20));

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

    public static string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
}
