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
    /// <summary>
    /// What one finding contributes to the weight that positions the score. Not a subtraction
    /// from 100: see <see cref="ScoreFor"/> for why these accumulate with diminishing effect.
    /// </summary>
    public static int WeightFor(Severity severity) => severity switch
    {
        Severity.Critical => 40,
        Severity.High => 20,
        Severity.Medium => 8,
        Severity.Low => 3,
        _ => 0,
    };

    /// <summary>
    /// The range the worst finding present confines the score to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The ceiling is the original design point and stays: one critical finding caps at 39 no
    /// matter how much else passed, so breadth of passing trivia cannot lift an application
    /// that ships a live key.
    /// </para>
    /// <para>
    /// The floor is the correction. Deductions used to subtract from 100 and clamp at zero,
    /// which meant three critical findings and forty produced the same number, and that number
    /// asserted something no static scan can know: that nothing measured about the application
    /// was acceptable. Zero is now reserved for the one case that earns it, which is a scan
    /// that could not read enough to say anything, and that is handled by the coverage gate
    /// rather than here.
    /// </para>
    /// <para>
    /// The bands line up with <see cref="BandFor"/> exactly and in both directions, so the
    /// number and the label can never disagree. That was previously true only downwards: five
    /// high findings and no critical ones scored zero and were labelled "critical issues",
    /// which named a severity the scan had not found.
    /// </para>
    /// </remarks>
    private static (int Floor, int Ceiling) RangeFor(Severity worst) => worst switch
    {
        Severity.Critical => (10, 39),
        Severity.High => (40, 69),
        Severity.Medium => (70, 89),
        Severity.Low => (90, 99),
        _ => (100, 100),
    };

    /// <summary>
    /// How quickly accumulated weight drives the score down its band. Chosen so that a single
    /// critical finding sits near the top of the critical band and a badly broken application
    /// approaches the bottom without ever reaching it, which keeps the number discriminating
    /// across the whole range instead of saturating a few findings in.
    /// </summary>
    private const double WeightScale = 100.0;

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
            Explanation = Explain(findings, audience),
            BlockingReasons = blocking
                .Select(f => f.Title)
                .Distinct(StringComparer.Ordinal)
                .ToList(),
        };
    }

    /// <summary>Records what drove the number, so the report can account for it.</summary>
    private static ScoreExplanation Explain(IReadOnlyList<Finding> findings, Audience audience)
    {
        var worst = findings.Count == 0
            ? Severity.Info
            : findings.Max(f => f.SeverityFor(audience));

        var (floor, ceiling) = RangeFor(worst);

        return new ScoreExplanation
        {
            Worst = worst,
            Floor = floor,
            Ceiling = ceiling,
            Counted = findings.Count(f => WeightFor(f.SeverityFor(audience)) > 0),
            Informational = findings.Count(f => WeightFor(f.SeverityFor(audience)) == 0),
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

    /// <summary>
    /// Places the score inside the band its worst finding allows.
    /// </summary>
    /// <remarks>
    /// The weight of everything found decides where in that band it lands, with each further
    /// finding moving it less than the one before. That is deliberate rather than a softening:
    /// the fifth critical finding tells a reader far less than the second did, and a model that
    /// weights them equally stops distinguishing between a bad application and a catastrophic
    /// one exactly where the distinction starts to matter.
    /// </remarks>
    private static int ScoreFor(IReadOnlyList<Finding> findings, Audience audience)
    {
        if (findings.Count == 0)
        {
            return 100;
        }

        var (floor, ceiling) = RangeFor(findings.Max(f => f.SeverityFor(audience)));

        if (floor == ceiling)
        {
            return ceiling;
        }

        var weight = findings.Sum(f => WeightFor(f.SeverityFor(audience)));

        // Approaches the floor without reaching it, so more findings always score lower than
        // fewer and the number never bottoms out into meaninglessness.
        var saturation = 1 - Math.Exp(-weight / WeightScale);

        return (int)Math.Round(ceiling - ((ceiling - floor) * saturation));
    }

    /// <summary>
    /// Maps a score to its band. Thresholds mirror <see cref="RangeFor"/> exactly, so the
    /// score always lands in the band its worst finding implies, and no band can be reported
    /// for a severity the scan did not find.
    /// </summary>
    private static ScoreBand BandFor(int score) => score switch
    {
        <= 39 => ScoreBand.CriticalIssues,
        <= 69 => ScoreBand.SeriousIssues,
        <= 89 => ScoreBand.NeedsWork,
        _ => ScoreBand.NoKnownIssues,
    };
}
