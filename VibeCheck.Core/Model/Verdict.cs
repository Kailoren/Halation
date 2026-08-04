namespace VibeCheck.Core.Model;

/// <summary>
/// The headline result: a score, its band, and whether anything found is serious enough
/// to advise against installing.
/// </summary>
/// <remarks>
/// Note what this type deliberately does not express: a claim that the artifact is safe.
/// A static analyser can demonstrate the presence of bad patterns but never their absence,
/// and a deliberately malicious app will read cleaner than a sloppy honest one. The band
/// names are worded accordingly, topping out at "no known issues found".
/// </remarks>
/// <summary>
/// Why the score is the number it is, in terms a reader can check against the finding list.
/// </summary>
public sealed record ScoreExplanation
{
    /// <summary>The worst severity found, which is what selects the band.</summary>
    public required Severity Worst { get; init; }

    public required int Floor { get; init; }

    public required int Ceiling { get; init; }

    /// <summary>Findings that carried weight.</summary>
    public required int Counted { get; init; }

    /// <summary>Findings recorded but deliberately weightless, so the reader is not left
    /// assuming everything in the list dragged the number down.</summary>
    public required int Informational { get; init; }

    /// <summary>
    /// Which of the two readings produced the score, and therefore which reader's severities
    /// the counts above were taken from.
    /// </summary>
    public required Audience GovernedBy { get; init; }

    /// <summary>What this artifact scores as a question about shipping it.</summary>
    public required int DeveloperReading { get; init; }

    /// <summary>What it scores as a question about running it.</summary>
    public required int EndUserReading { get; init; }

    /// <summary>Phrased once here so the exported report and the window cannot disagree.</summary>
    public IReadOnlyList<string> Describe()
    {
        var lines = new List<string>();

        // Named when the two readings disagree, because then the counts below are taken from
        // the governing one and will not match the list the reader is looking at. An end user
        // told "2 findings count" while one of theirs is marked informational is owed the
        // reason in the same breath.
        var reading = DeveloperReading == EndUserReading
            ? string.Empty
            : $"Read {GovernedBy.Reading()}, ";

        if (Counted == 0)
        {
            lines.Add(reading.Length == 0
                ? "Nothing found that affects the score."
                : $"{reading}nothing found affects the score.");
        }
        else
        {
            var worst = reading.Length == 0
                ? $"The worst finding is {Worst}"
                : $"{reading}the worst finding is {Worst}";

            lines.Add(Floor == Ceiling
                ? $"{worst}, which does not move the score."
                : $"{worst}, which places this between {Floor} and "
                  + $"{Ceiling}. Where it sits in that range is decided by "
                  + (Counted == 1
                      ? "the one finding that counts."
                      : $"all {Counted} findings that count, with each further one moving it "
                        + "less than the last."));
        }

        if (Informational > 0)
        {
            lines.Add($"{Informational} informational finding"
                      + $"{(Informational == 1 ? " is" : "s are")} listed but "
                      + "did not affect the score.");
        }

        // Named rather than left to be noticed. Somebody who switches reader and sees the
        // number stay put deserves to know it is deliberate, and somebody who wondered why
        // this artifact scores what it does deserves to see both answers.
        if (DeveloperReading != EndUserReading)
        {
            var other = GovernedBy == Audience.Developer ? Audience.EndUser : Audience.Developer;
            var otherScore = GovernedBy == Audience.Developer ? EndUserReading : DeveloperReading;

            lines.Add(
                $"That reading scores {Math.Min(DeveloperReading, EndUserReading)}; read "
                + $"{other.Reading()}, {otherScore}. The lower of the two is shown to both "
                + "readers, so no report can be made to look better by switching reader.");
        }

        return lines;
    }
}

public sealed record Verdict
{
    /// <summary>0-100, capped by the worst finding present.</summary>
    public required int Score { get; init; }

    public required ScoreBand Band { get; init; }

    /// <summary>
    /// True when at least one blocking rule fired. Driven only by specific deterministic
    /// rules, never by the aggregate score and never by the assisted deep pass.
    /// </summary>
    public required bool AdviseAgainstInstall { get; init; }

    /// <summary>The specific findings behind <see cref="AdviseAgainstInstall"/>.</summary>
    public IReadOnlyList<string> BlockingReasons { get; init; } = [];

    /// <summary>
    /// Which report this verdict was rendered for.
    /// </summary>
    /// <remarks>
    /// Which findings are shown, how they are worded and what order they come in. Not which
    /// question <see cref="Score"/> answers: the score is the lower of both readings and is the
    /// same in either report. See <see cref="Scoring.ScoreCalculator"/>.
    /// </remarks>
    public required Audience Audience { get; init; }

    /// <summary>
    /// How the number was arrived at. Null when no score was produced.
    /// </summary>
    /// <remarks>
    /// A score nobody can account for is a score nobody trusts, and this one is not a simple
    /// subtraction: the worst finding decides which band applies, and everything else decides
    /// where in that band it lands. Left unexplained, a reader seeing a low number has no way
    /// to tell a scan that found one serious problem from one that found forty.
    /// </remarks>
    public ScoreExplanation? Explanation { get; init; }

    /// <summary>
    /// What the number is, for display immediately beneath it.
    /// </summary>
    /// <remarks>
    /// Not optional furniture, and no longer a per-reader caption. The artifact reads
    /// differently for the person shipping it and the person running it, and the score is the
    /// worse of those two readings so that neither report flatters the artifact relative to
    /// the other. A number that did not say that would look like it answered whichever question
    /// the reader happened to be asking. No display path should render
    /// <see cref="ScoreDisplay"/> without this beside it.
    /// </remarks>
    public string ScoreCaption => SharedScoreCaption;

    /// <summary>Phrased once, because the exported report and the window must not differ.</summary>
    public const string SharedScoreCaption =
        "Whichever is worse: the risk in shipping this, or the risk in running it";

    /// <summary>
    /// Whether a numeric score is meaningful for this result. False when too little of the
    /// artifact could be read; callers should show <see cref="BandLabel"/> alone rather than
    /// a number that would imply the application was examined.
    /// </summary>
    public bool HasMeaningfulScore => Band != ScoreBand.InsufficientCoverage;

    /// <summary>
    /// The headline result as it should be shown, in one place.
    /// </summary>
    /// <remarks>
    /// <see cref="Score"/> still holds a number when <see cref="HasMeaningfulScore"/> is
    /// false, because the deduction arithmetic ran over whatever findings did exist. Rendering
    /// that number would tell the reader the application scored well when in fact it was never
    /// read. Every display path should use this rather than formatting the score itself.
    /// </remarks>
    public string ScoreDisplay => HasMeaningfulScore ? $"{Score}/100" : "Not scored";

    /// <summary>Short label for the band, for display next to the score.</summary>
    public string BandLabel => Band switch
    {
        ScoreBand.CriticalIssues => "Critical issues",
        ScoreBand.SeriousIssues => "Serious issues",
        ScoreBand.NeedsWork => "Needs work",
        ScoreBand.NoKnownIssues => "No known issues found",
        ScoreBand.InsufficientCoverage => "Could not analyse",
        _ => "Unknown",
    };
}
