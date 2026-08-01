namespace VibeCheck.Core.Model;

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

    public static CoverageReport None(string basis) => new()
    {
        Percent = 0,
        Basis = basis,
    };
}

