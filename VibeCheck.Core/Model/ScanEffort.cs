using VibeCheck.Core.Dependencies;

namespace VibeCheck.Core.Model;

/// <summary>
/// What the scan actually did, stated in countable terms.
/// </summary>
/// <remarks>
/// A hundred-megabyte application finishes in under two seconds, which reads as though nothing
/// happened. The honest answer is to print the receipt rather than to slow the scan down or
/// animate a longer progress bar: a tool whose claim is that it says what it did cannot
/// manufacture the appearance of effort. The dependency line is the load-bearing one, being the
/// only claim here that cannot be fabricated.
/// </remarks>
public sealed record ScanEffort
{
    /// <summary>How the source was obtained, in the reader's terms rather than a backend name.</summary>
    public required string RecoveryMethod { get; init; }

    public required int FilesRecovered { get; init; }

    public required long BytesRecovered { get; init; }

    /// <summary>Rules in the catalog that ran, not the number that matched.</summary>
    public required int ChecksRun { get; init; }

    public required int FilesChecked { get; init; }

    /// <summary>Packages pinned to an exact version, and so checkable.</summary>
    public required int PackagesResolved { get; init; }

    /// <summary>Of those, how many an advisory database actually answered for.</summary>
    public required int PackagesChecked { get; init; }

    /// <summary>
    /// Manifests that named dependencies without pinning them.
    /// </summary>
    /// <remarks>
    /// The difference between an application with no dependencies and one whose dependencies
    /// cannot be read. Both resolve nothing; only the second has a gap worth telling the
    /// reader about. See <see cref="ScanReport.DependencyCaveat"/>.
    /// </remarks>
    public int ManifestsUnresolved { get; init; }

    public required VulnerabilityDataProvenance VulnerabilityData { get; init; }

    /// <summary>
    /// Matches the scanner decided were rule table entries rather than code.
    /// </summary>
    /// <remarks>
    /// On the receipt rather than swallowed. A tool that quietly removes its own findings is
    /// asking to be trusted about the one thing nobody can check, so the count is stated and
    /// the reason with it. Normally zero; it is other detection tools, and this one, that
    /// carry every string they search for in quotation marks.
    /// </remarks>
    public int MatchesDiscounted { get; init; }

    /// <summary>
    /// The receipt, as lines to render. Anything that did not happen is omitted rather than
    /// reported as a zero, so the list never pads itself out with work that was not done.
    /// </summary>
    public IReadOnlyList<string> Describe(DateTimeOffset scannedAt)
    {
        var lines = new List<string>();

        if (FilesRecovered > 0)
        {
            lines.Add(
                $"Recovered {FilesRecovered:N0} file{(FilesRecovered == 1 ? "" : "s")} "
                + $"({FormatBytes(BytesRecovered)}) by {RecoveryMethod}.");
        }
        else
        {
            lines.Add($"No source could be recovered: {RecoveryMethod}.");
        }

        if (FilesChecked > 0)
        {
            lines.Add(
                $"Ran {ChecksRun:N0} checks against {FilesChecked:N0} "
                + $"file{(FilesChecked == 1 ? "" : "s")}.");
        }

        if (MatchesDiscounted > 0)
        {
            lines.Add(
                $"Discounted {MatchesDiscounted:N0} match{(MatchesDiscounted == 1 ? "" : "es")} "
                + "that sat inside search patterns rather than in code that runs. This "
                + "application appears to contain a table of detection rules, and a scanner "
                + "reading one finds every string it is looking for.");
        }

        if (PackagesChecked > 0)
        {
            lines.Add(
                $"Resolved {PackagesResolved:N0} packages and checked {PackagesChecked:N0} of them "
                + $"against {VulnerabilityData.Describe(scannedAt)}.");
        }
        else if (PackagesResolved > 0)
        {
            lines.Add(
                $"Resolved {PackagesResolved:N0} packages, none of which could be checked: "
                + $"{VulnerabilityData.Describe(scannedAt)}.");
        }

        return lines;
    }

    /// <summary>Names the recovery route for the reader, from what the artifact turned out to be.</summary>
    public static string MethodFor(ArtifactKind kind) => kind switch
    {
        ArtifactKind.DotNetAssembly or ArtifactKind.DotNetSingleFile => "decompilation",
        ArtifactKind.JavaArchive => "decompilation",
        ArtifactKind.ElectronApp or ArtifactKind.AsarArchive => "unpacking the asar archive",
        ArtifactKind.WindowsInstaller => "unpacking the installer",
        ArtifactKind.PythonBundle => "unpacking the Python bundle",
        ArtifactKind.SourceTree => "reading the source directly",
        ArtifactKind.Archive => "unpacking the archive",
        ArtifactKind.NativeWindows => "a native binary cannot be decompiled to analysable source",
        _ => "reading what could be identified",
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024 * 1024):N1} GB",
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024):N1} MB",
        >= 1024 => $"{bytes / 1024.0:N0} KB",
        _ => $"{bytes:N0} bytes",
    };
}
