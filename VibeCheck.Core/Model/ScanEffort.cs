using VibeCheck.Core.Dependencies;

namespace VibeCheck.Core.Model;

/// <summary>
/// What the scan actually did, stated in countable terms.
/// </summary>
/// <remarks>
/// <para>
/// A scan of a hundred-megabyte application finishes in under two seconds, which reads as
/// though nothing happened. The work is real - locating a payload inside an installer,
/// decompiling a few hundred files, running the catalog over all of them, resolving packages
/// and asking a remote database about every one of them - but the report only ever showed the
/// conclusions, so the reader had nothing to weigh the speed against.
/// </para>
/// <para>
/// The honest fix is to print the receipt, not to slow the scan down or animate a progress bar
/// for longer than the work takes. A tool whose entire claim is that it tells you what it did
/// and did not check cannot manufacture the appearance of effort; if that were ever noticed,
/// every other statement in the report would deserve the same suspicion.
/// </para>
/// <para>
/// The dependency line is the load-bearing one, because it is the only claim here that cannot
/// be fabricated: it names an external service and the moment it answered.
/// </para>
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

    public required VulnerabilityDataProvenance VulnerabilityData { get; init; }

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
