using System.Diagnostics;
using System.Reflection;

using VibeCheck.Core.Artifacts;
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
    Scoring,
    Complete,
}

public sealed record ScanProgress(ScanStage Stage, string Message, int? Percent = null);

/// <summary>
/// Runs a complete scan: identify the artifact, recover what source it has, apply the rule
/// catalog, and score the result.
/// </summary>
/// <remarks>
/// Nothing here touches the network and nothing is written outside memory, so a scan is safe
/// to run on a machine with no connectivity and on an artifact assumed to be hostile.
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
            new SourceRecoveryBackend(),
            new NativeRecoveryBackend(),
        ];

        _rules = rules ?? new RuleEngine();
    }

    public async Task<ScanReport> ScanAsync(
        string path,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

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

        progress?.Report(new ScanProgress(ScanStage.Scoring, "Scoring results"));

        // Three stages contribute findings and all are equally real, they were just observed
        // at different depths: packaging looks at which files ship, recovery at the binary
        // itself, and the rule pass at recovered source.
        var findings = PackagingChecks.Run(artifact)
            .Concat(recovery.Findings)
            .Concat(analysis.Findings)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();

        var coverage = MergeCoverage(recovery.Coverage, analysis, VulnerabilityDatabase.Current);

        var report = new ScanReport
        {
            ArtifactName = artifact.Name,
            Kind = artifact.Kind,
            ArtifactBytes = artifact.Bytes,
            Sha256 = sha256,
            ScannedAt = DateTimeOffset.Now,

            // Coverage gates the verdict: without it, an artifact that yielded no readable
            // code at all scores full marks for the absence of findings that were never
            // looked for.
            Verdict = ScoreCalculator.Calculate(findings, coverage.Percent),
            Coverage = coverage,
            Findings = findings,
            CategoryScores = ScoreCalculator.CategoryScores(findings),
            VulnerabilityData = VulnerabilityDatabase.Current,
            ScannerVersion = Version,
            Duration = stopwatch.Elapsed,
        };

        progress?.Report(new ScanProgress(ScanStage.Complete, "Scan complete", 100));

        return report;
    }

    /// <summary>
    /// Folds everything that did not actually run into the coverage report.
    /// </summary>
    /// <remarks>
    /// A check that timed out, or a whole category with no data behind it, must never be
    /// presented as a check that found nothing. Without this, a report showing no dependency
    /// findings reads as "dependencies are clean" when the truth is that no vulnerability
    /// data was available to compare them against.
    /// </remarks>
    private static CoverageReport MergeCoverage(
        CoverageReport coverage,
        RuleEngineResult analysis,
        VulnerabilityDataInfo vulnerabilityData)
    {
        var limitations = new List<string>(coverage.ChecksNotPossible);

        limitations.AddRange(analysis.Limitations);

        if (vulnerabilityData.AdvisoryCount == 0)
        {
            limitations.Add(
                "Dependency vulnerabilities were not checked: this build has no bundled "
                + "vulnerability data.");
        }

        return limitations.Count == coverage.ChecksNotPossible.Count
            ? coverage
            : coverage with { ChecksNotPossible = limitations };
    }

    public static string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
}

/// <summary>
/// The bundled vulnerability data used for dependency checks.
/// </summary>
/// <remarks>
/// Ships inside the application so dependency scanning works with no network. Until the
/// snapshot is populated the count is reported as zero, which the report renders as
/// "dependency checks unavailable" rather than as a clean dependency result.
/// </remarks>
public static class VulnerabilityDatabase
{
    public static VulnerabilityDataInfo Current { get; } = new()
    {
        SnapshotDate = new DateOnly(2026, 8, 1),
        AdvisoryCount = 0,
    };
}
