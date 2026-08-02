namespace VibeCheck.Core.Model;

/// <summary>
/// The complete result of one scan. This is what the in-app report view renders and what
/// the Markdown and JSON exporters serialise, so it must be self-contained: everything
/// needed to interpret the result, including what could not be checked, lives here.
/// </summary>
public sealed record ScanReport
{
    /// <summary>File name of the scanned artifact. The full local path is deliberately
    /// not carried here, so an exported report does not leak the user's directory layout.</summary>
    public required string ArtifactName { get; init; }

    public required ArtifactKind Kind { get; init; }

    /// <summary>Size of the dropped artifact in bytes.</summary>
    public required long ArtifactBytes { get; init; }

    /// <summary>SHA-256 of the artifact, so a result can be tied to an exact file.</summary>
    public required string Sha256 { get; init; }

    public required DateTimeOffset ScannedAt { get; init; }

    public required Verdict Verdict { get; init; }

    public required CoverageReport Coverage { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>Per-category subscores, on the same 0-100 scale as the overall score.</summary>
    public required IReadOnlyDictionary<FindingCategory, int> CategoryScores { get; init; }

    public required Dependencies.VulnerabilityDataProvenance VulnerabilityData { get; init; }

    /// <summary>
    /// What the scan did, so its speed can be read as fast rather than as skipped.
    /// </summary>
    public required ScanEffort Effort { get; init; }

    /// <summary>
    /// Where the offline data bundle for this scan was written, when one was produced.
    /// </summary>
    public string? BundlePath { get; init; }

    /// <summary>True when the scan made no network calls of any kind.</summary>
    public bool RanIsolated { get; init; }

    /// <summary>Whether the optional BYOK deep pass contributed to this report.</summary>
    public bool DeepPassRan { get; init; }

    /// <summary>
    /// What the deep pass cost the key holder, in US dollars, or null when it did not run.
    /// Stated because the reader is paying for it on their own account and has no other bill
    /// until it appears on their console a day later.
    /// </summary>
    public decimal? DeepPassCost { get; init; }

    /// <summary>Version of the scanner that produced this report.</summary>
    public required string ScannerVersion { get; init; }

    /// <summary>How long the scan took, for the UI and for spotting pathological inputs.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>Findings ordered worst-first, which is how every view wants them.</summary>
    public IEnumerable<Finding> FindingsBySeverity =>
        Findings.OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .ThenBy(f => f.RuleId, StringComparer.Ordinal);

    public int CountOf(Severity severity) => Findings.Count(f => f.Severity == severity);

    /// <summary>Human-readable kind, for headers and exports.</summary>
    public string KindLabel => Kind switch
    {
        ArtifactKind.DotNetAssembly => ".NET assembly",
        ArtifactKind.DotNetSingleFile => ".NET single-file application",
        ArtifactKind.NativeWindows => "Native Windows binary",
        ArtifactKind.WindowsInstaller => "Windows installer",
        ArtifactKind.ElectronApp => "Electron application",
        ArtifactKind.AsarArchive => "Electron asar archive",
        ArtifactKind.JavaArchive => "Java archive",
        ArtifactKind.PythonBundle => "Python bundle",
        ArtifactKind.SourceTree => "Source tree",
        ArtifactKind.Archive => "Archive",
        _ => "Unrecognised artifact",
    };
}
