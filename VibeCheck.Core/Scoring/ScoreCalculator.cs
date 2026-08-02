using VibeCheck.Core.Model;

namespace VibeCheck.Core.Scoring;

/// <summary>
/// Turns a set of findings into the headline score, band, and install verdict.
/// </summary>
/// <remarks>
/// <para>
/// The design point here is the cap. Scores that average across many checks reward breadth
/// of passing trivia: an app can pass fifty header-style checks, ship a live API key in its
/// bundle, and still score in the nineties. That number is worse than no number, because it
/// actively tells the reader the app is fine.
/// </para>
/// <para>
/// So deductions accumulate normally, and then the score is hard-capped by the single worst
/// finding present. Any critical finding caps at 39 no matter what else passed. Fifty clean
/// checks cannot lift an app with a leaked service key out of the red band.
/// </para>
/// </remarks>
public static class ScoreCalculator
{
    /// <summary>Points removed per finding, by severity. Multiple issues compound.</summary>
    private static int DeductionFor(Severity severity) => severity switch
    {
        Severity.Critical => 40,
        Severity.High => 20,
        Severity.Medium => 8,
        Severity.Low => 3,
        _ => 0,
    };

    /// <summary>
    /// The hard ceiling implied by the worst finding present. These align with the band
    /// thresholds so the number and the label can never disagree.
    /// </summary>
    private static int CapFor(Severity worst) => worst switch
    {
        Severity.Critical => 39,
        Severity.High => 69,
        Severity.Medium => 89,
        _ => 100,
    };

    /// <summary>
    /// Coverage at or below this percentage means no score is reported.
    /// </summary>
    /// <remarks>
    /// Set from observed behaviour rather than intuition: scanning a self-contained
    /// single-file application yielded zero readable code and, before this gate existed,
    /// a confident "100/100, no known issues found".
    /// </remarks>
    public const int MinimumMeaningfulCoverage = 5;

    /// <summary>Computes the overall verdict for a complete finding set.</summary>
    /// <param name="findings">Everything found, from every stage.</param>
    /// <param name="coveragePercent">
    /// How much of the artifact was readable. Below <see cref="MinimumMeaningfulCoverage"/>,
    /// the verdict refuses to score rather than reporting a high one, because a scan that
    /// read nothing has found nothing for reasons that say nothing about the application.
    /// </param>
    /// <param name="audience">
    /// Which question the score answers. Findings carry a severity per audience, so the same
    /// artifact legitimately scores differently for the person shipping it and the person
    /// running it. The verdict records which one it answered; every display path must show
    /// that alongside the number.
    /// </param>
    public static Verdict Calculate(
        IReadOnlyList<Finding> findings,
        int coveragePercent = 100,
        Audience audience = Audience.Developer)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var score = ScoreFor(findings, audience);

        // Findings can still exist at zero coverage: a native binary yields signing and
        // hardening observations without a line of source. Those are reported, but they do
        // not license a score for the application as a whole.
        if (coveragePercent < MinimumMeaningfulCoverage)
        {
            var blockingAtLowCoverage = findings
                .Where(f => f.IsBlocking && f.Source == FindingSource.Rule)
                .ToList();

            return new Verdict
            {
                Score = score,
                Band = blockingAtLowCoverage.Count > 0
                    ? ScoreBand.CriticalIssues
                    : ScoreBand.InsufficientCoverage,
                AdviseAgainstInstall = blockingAtLowCoverage.Count > 0,
                Audience = audience,
                BlockingReasons = blockingAtLowCoverage
                    .Select(f => f.Title)
                    .Distinct(StringComparer.Ordinal)
                    .ToList(),
            };
        }

        // Only deterministic rules may advise against installation. An inferred finding is
        // not a defensible basis for telling someone not to run software they downloaded,
        // and the deep pass is optional, so letting it block would make the strongest claim
        // in the report depend on whether the user happened to supply an API key.
        var blocking = findings
            .Where(f => f.IsBlocking && f.Source == FindingSource.Rule)
            .ToList();

        return new Verdict
        {
            Score = score,
            Band = BandFor(score),
            AdviseAgainstInstall = blocking.Count > 0,
            Audience = audience,
            BlockingReasons = blocking
                .Select(f => f.Title)
                .Distinct(StringComparer.Ordinal)
                .ToList(),
        };
    }

    /// <summary>
    /// Per-category subscores, so the headline number is explainable. Categories with no
    /// findings score 100; that means "nothing found here", which the report states plainly
    /// alongside the coverage meter rather than implying the category is clean.
    /// </summary>
    public static IReadOnlyDictionary<FindingCategory, int> CategoryScores(
        IReadOnlyList<Finding> findings,
        Audience audience = Audience.Developer)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return Enum.GetValues<FindingCategory>()
            .ToDictionary(
                category => category,
                category => ScoreFor(
                    findings.Where(f => f.Category == category).ToList(), audience));
    }

    /// <summary>Applies accumulated deductions, then the worst-finding cap.</summary>
    private static int ScoreFor(IReadOnlyList<Finding> findings, Audience audience)
    {
        if (findings.Count == 0)
        {
            return 100;
        }

        var score = 100 - findings.Sum(f => DeductionFor(f.SeverityFor(audience)));
        var cap = CapFor(findings.Max(f => f.SeverityFor(audience)));

        return Math.Clamp(Math.Min(score, cap), 0, 100);
    }

    /// <summary>
    /// Maps a score to its band. Thresholds mirror <see cref="CapFor"/> exactly, so a
    /// capped score always lands in the band its worst finding implies.
    /// </summary>
    private static ScoreBand BandFor(int score) => score switch
    {
        <= 39 => ScoreBand.CriticalIssues,
        <= 69 => ScoreBand.SeriousIssues,
        <= 89 => ScoreBand.NeedsWork,
        _ => ScoreBand.NoKnownIssues,
    };
}
