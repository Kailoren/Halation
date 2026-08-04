using VibeCheck.Core.Model;

namespace VibeCheck.Core.Scoring;

/// <summary>
/// Turns a set of findings into the headline score, band, and install verdict.
/// </summary>
/// <remarks>
/// <para>
/// The design point is the cap. Averaging across checks rewards breadth of passing trivia: an
/// app can pass fifty of them, ship a live API key, and score in the nineties, which is worse
/// than no number at all. Deductions accumulate normally and the score is then hard-capped by
/// the single worst finding, so any critical caps at 39 whatever else passed.
/// </para>
/// <para>
/// <b>Both readings are computed and the lower one is the score, for both readers.</b> Findings
/// carry a severity per audience, so the same artifact genuinely reads differently for whoever
/// ships it and whoever runs it, and the report still says both. What it will not do is let the
/// kinder of the two be the headline: an author who scans their own work, switches to the end
/// user view and screenshots the higher number would be publishing a number this tool produced
/// for a different question. The findings, the wording and the remediation still change with
/// the reader. Only the number does not.
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
    /// The floor is the part worth explaining. Deductions used to clamp at zero, so three
    /// critical findings and forty produced the same number, which asserted something no static
    /// scan can know. Zero is reserved for a scan that could not read enough to say anything,
    /// and the coverage gate handles that. Bands line up with <see cref="BandFor"/> in both
    /// directions so the number and the label cannot disagree.
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
    /// Which report is being rendered. It decides the findings' severities, their wording and
    /// their order, and it breaks a tie over which reading the account beneath the score
    /// describes. It does <b>not</b> decide the number: see the remarks on this class.
    /// </param>
    public static Verdict Calculate(
        IReadOnlyList<Finding> findings,
        int coveragePercent = 100,
        Audience audience = Audience.Developer)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var developer = ScoreFor(findings, Audience.Developer);
        var endUser = ScoreFor(findings, Audience.EndUser);

        var score = Math.Min(developer, endUser);

        // Which reading produced the number, so the account below it describes arithmetic that
        // really ran rather than the reader's own. Where the two agree it is attributed to
        // whoever is reading, whose finding list then matches it exactly.
        var governing = developer == endUser
            ? audience
            : developer < endUser
                ? Audience.Developer
                : Audience.EndUser;

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
            Explanation = Explain(findings, governing, developer, endUser),
            BlockingReasons = blocking
                .Select(f => f.Title)
                .Distinct(StringComparer.Ordinal)
                .ToList(),
        };
    }

    /// <summary>Records what drove the number, so the report can account for it.</summary>
    /// <remarks>
    /// Built from the reading that governed rather than from the reader's own, or the account
    /// would describe a band and a count that do not add up to the number printed above them.
    /// Both readings travel with it so the difference can be named instead of looking like a
    /// glitch when somebody switches reader and the number stays put.
    /// </remarks>
    private static ScoreExplanation Explain(
        IReadOnlyList<Finding> findings,
        Audience governing,
        int developerReading,
        int endUserReading)
    {
        var worst = findings.Count == 0
            ? Severity.Info
            : findings.Max(f => f.SeverityFor(governing));

        var (floor, ceiling) = RangeFor(worst);

        return new ScoreExplanation
        {
            Worst = worst,
            Floor = floor,
            Ceiling = ceiling,
            Counted = findings.Count(f => WeightFor(f.SeverityFor(governing)) > 0),
            Informational = findings.Count(f => WeightFor(f.SeverityFor(governing)) == 0),
            GovernedBy = governing,
            DeveloperReading = developerReading,
            EndUserReading = endUserReading,
        };
    }

    /// <summary>
    /// Per-category subscores, so the headline number is explainable. Categories with no
    /// findings score 100; that means "nothing found here", which the report states plainly
    /// alongside the coverage meter rather than implying the category is clean.
    /// </summary>
    /// <remarks>
    /// The lower of the two readings, per category, for the same reason the headline is: a
    /// breakdown that softened when the reader changed would let the same screenshot be taken
    /// one card further down.
    /// </remarks>
    public static IReadOnlyDictionary<FindingCategory, int> CategoryScores(
        IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return Enum.GetValues<FindingCategory>()
            .ToDictionary(
                category => category,
                category =>
                {
                    var inCategory = findings.Where(f => f.Category == category).ToList();

                    return Math.Min(
                        ScoreFor(inCategory, Audience.Developer),
                        ScoreFor(inCategory, Audience.EndUser));
                });
    }

    /// <summary>
    /// Places the score inside the band its worst finding allows.
    /// </summary>
    /// <remarks>
    /// Each further finding moves the score less than the one before, because the fifth
    /// critical tells a reader far less than the second did.
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
