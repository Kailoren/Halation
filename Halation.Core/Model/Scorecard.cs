namespace Halation.Core.Model;

/// <summary>
/// Everything that goes on the exported scorecard image, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// Separated from the drawing so it can be tested, and so the decision about <b>what a badge is
/// allowed to claim</b> is made here rather than inside a rendering routine.
/// </para>
/// <para>
/// Three of these fields are load-bearing rather than decoration, and a scorecard without them
/// would be the exact artifact the rest of this product exists to prevent:
/// </para>
/// <list type="bullet">
/// <item><see cref="CoveragePercent"/>, because a score means nothing without it. Ninety-nine out
/// of a hundred against 12% of an application is not the same claim as the same number against
/// all of it, and a badge showing only the number invites it to be read as the second.</item>
/// <item><see cref="Sha256"/>, because it is the only thing that makes the image checkable. An
/// image proves nothing on its own; anybody can draw one. The hash says which exact file was
/// scanned, so a reader can run the same scan and see whether they get the same answer.</item>
/// <item><see cref="ScannerVersion"/>, because the rules change between versions and a score is
/// only reproducible against the build that produced it.</item>
/// </list>
/// </remarks>
public sealed record Scorecard
{
    /// <summary>The name of what was scanned.</summary>
    public required string ArtifactName { get; init; }

    /// <summary>The score, or null when coverage was too low for one to be produced.</summary>
    public required int? Score { get; init; }

    /// <summary>The band in words, which is what the number actually means.</summary>
    public required string Band { get; init; }

    /// <summary>How much of the application could be read.</summary>
    public required int CoveragePercent { get; init; }

    public required int Critical { get; init; }

    public required int High { get; init; }

    public required int Medium { get; init; }

    public required int Low { get; init; }

    /// <summary>Findings that count for nothing, listed so the totals add up.</summary>
    public required int Info { get; init; }

    /// <summary>The hash of the file that was scanned. Empty for a source tree.</summary>
    public required string Sha256 { get; init; }

    public required DateTimeOffset ScannedAt { get; init; }

    public required string ScannerVersion { get; init; }

    /// <summary>Findings that count towards the score.</summary>
    public int Counted => Critical + High + Medium + Low;

    /// <summary>The score as it is written, or a refusal when there is not one.</summary>
    /// <remarks>
    /// Below the coverage floor no score is produced at all, and the card has to say so rather
    /// than draw a zero. A zero would read as "scored badly" when the truth is "not scored".
    /// </remarks>
    public string ScoreDisplay => Score is { } score ? $"{score}/100" : "not scored";

    /// <summary>Critical, high, medium and low, in the compact form used on the card.</summary>
    public string CountsDisplay => $"{Critical}/{High}/{Medium}/{Low}";

    /// <summary>
    /// How somebody else checks this rather than taking it on trust.
    /// </summary>
    public string VerificationLine => string.IsNullOrEmpty(Sha256)
        ? $"Scanned with Halation {ScannerVersion}. Rescan the same source to check this."
        : $"Scanned with Halation {ScannerVersion}. Rescan the file with this hash to check this.";

    /// <summary>Takes the card's facts off a finished report.</summary>
    public static Scorecard From(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var counts = report.Findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        int Count(Severity severity) => counts.TryGetValue(severity, out var n) ? n : 0;

        return new Scorecard
        {
            ArtifactName = report.ArtifactName,

            // Null rather than the raw number when the verdict says the number means nothing.
            Score = report.Verdict.HasMeaningfulScore ? report.Verdict.Score : null,
            Band = report.Verdict.BandLabel,

            CoveragePercent = report.Coverage.Percent,

            Critical = Count(Severity.Critical),
            High = Count(Severity.High),
            Medium = Count(Severity.Medium),
            Low = Count(Severity.Low),
            Info = Count(Severity.Info),

            Sha256 = report.Sha256,
            ScannedAt = report.ScannedAt,
            ScannerVersion = report.ScannerVersion,
        };
    }
}
