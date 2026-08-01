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

/// <summary>
/// Provenance of the bundled vulnerability data.
/// </summary>
/// <remarks>
/// The database ships inside the app so dependency scanning works air-gapped. That makes
/// its age a first-class part of the result: a clean dependency report from a six-month-old
/// snapshot is a different claim from a clean one from yesterday, so the date is stamped
/// on every report rather than being a settings-screen detail.
/// </remarks>
public sealed record VulnerabilityDataInfo
{
    /// <summary>When the bundled snapshot was published.</summary>
    public required DateOnly SnapshotDate { get; init; }

    /// <summary>Number of advisories in the snapshot.</summary>
    public required int AdvisoryCount { get; init; }

    /// <summary>True when the snapshot is old enough to warrant a refresh prompt.</summary>
    public bool IsStale(DateOnly today, int stalenessDays = 30) =>
        today.DayNumber - SnapshotDate.DayNumber > stalenessDays;

    public string Describe() => $"{AdvisoryCount:N0} advisories, as of {SnapshotDate:yyyy-MM-dd}";
}
