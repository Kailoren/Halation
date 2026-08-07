namespace Halation.Core.Model;

/// <summary>
/// How much of the artifact could actually be read.
/// </summary>
/// <remarks>
/// Deliberately kept separate from the score rather than blended into it. A clean result
/// on an Electron app (where nearly all source is recoverable) means far more than a clean
/// result on a native binary (where almost none is), and a single blended number would
/// hide exactly that difference. Showing both lets the reader discount appropriately.
/// </remarks>
public sealed record CoverageReport
{
    /// <summary>0-100. Share of the artifact's code that produced analysable source.</summary>
    public required int Percent { get; init; }

    /// <summary>Plain-language basis for the figure, shown under the meter.</summary>
    public required string Basis { get; init; }

    /// <summary>
    /// Checks that could not run against this artifact kind. Surfaced in the report so a
    /// clean result is never mistaken for a complete one.
    /// </summary>
    public IReadOnlyList<string> ChecksNotPossible { get; init; } = [];

    /// <summary>Bytes of source successfully recovered.</summary>
    public long RecoveredBytes { get; init; }

    /// <summary>Number of files available to the rule engine.</summary>
    public int RecoveredFileCount { get; init; }

    /// <summary>
    /// Share of the recovered code, 0-100, that arrived minified rather than as something a
    /// person could read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Recovered is not the same as readable, and until this existed the report could not tell
    /// the difference. A real application was read in full, reported "100% readable, no known
    /// issues found", and was 99% minified: every quoted line of evidence in it was a fragment
    /// of a bundle several thousand characters wide, which tells a reader checking the finding
    /// for themselves precisely nothing.
    /// </para>
    /// <para>
    /// Kept out of <see cref="Percent"/> rather than folded into it. The rules do still run,
    /// and since matches are no longer collapsed per line they now find the same things here as
    /// in readable source, so deducting coverage would understate what was actually checked.
    /// What genuinely degrades is the reader's ability to verify any of it, and that is a
    /// caveat rather than a smaller number.
    /// </para>
    /// </remarks>
    public int MinifiedPercent { get; init; }

    public static CoverageReport None(string basis) => new()
    {
        Percent = 0,
        Basis = basis,
    };
}

