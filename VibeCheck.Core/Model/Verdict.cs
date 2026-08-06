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

/// <summary>
/// What the report advises about installing the artifact.
/// </summary>
/// <remarks>
/// Three states rather than two, because a declared purpose creates a case that neither of the
/// old ones described. An application doing something that would otherwise block, which the
/// person scanning has said it has a reason for, is not the same as one where nothing was
/// found: the behaviour is still there, still reported, and still worth the reader seeing.
/// Collapsing it into silence would let a declaration turn a warning into an all-clear, which
/// is the failure this whole feature has to avoid being.
/// </remarks>
public enum InstallAdvice
{
    /// <summary>Nothing was found that bears on installing it.</summary>
    None,

    /// <summary>
    /// Behaviour that would otherwise advise against installing, accounted for by what the
    /// application was said to be for. Reported plainly rather than suppressed.
    /// </summary>
    ConsistentWithStatedPurpose,

    /// <summary>At least one blocking rule fired and nothing accounts for it.</summary>
    AdviseAgainst,
}

public sealed record Verdict
{
    /// <summary>0-100, capped by the worst finding present.</summary>
    public required int Score { get; init; }

    public required ScoreBand Band { get; init; }

    /// <summary>
    /// What this report advises about installing the artifact. Driven only by specific
    /// deterministic rules, never by the aggregate score and never by the assisted deep pass.
    /// </summary>
    public required InstallAdvice Advice { get; init; }

    /// <summary>
    /// True when at least one blocking rule fired and nothing accounted for it.
    /// </summary>
    /// <remarks>
    /// Derived rather than stored, so it cannot drift from <see cref="Advice"/>. Behaviour
    /// explained by a stated purpose is deliberately false here: it belongs in its own state,
    /// not folded into the one that means nothing was wrong.
    /// </remarks>
    public bool AdviseAgainstInstall => Advice == InstallAdvice.AdviseAgainst;

    /// <summary>The specific findings behind <see cref="AdviseAgainstInstall"/>.</summary>
    public IReadOnlyList<string> BlockingReasons { get; init; } = [];

    /// <summary>
    /// Behaviour that would have advised against installing, and what accounted for it.
    /// </summary>
    /// <remarks>
    /// Carried on the verdict rather than left for a reader to find further down. A result that
    /// went quiet because somebody vouched for the application should say so where the number
    /// is, including in an exported copy that a different person is reading.
    /// </remarks>
    public IReadOnlyList<string> AccountedFor { get; init; } = [];

    /// <summary>
    /// Deep pass findings that were reported but took no part in the score.
    /// </summary>
    /// <remarks>
    /// Counted on the verdict rather than left to be discovered further down the report. The
    /// number above is deterministic so that two readers with two different models can compare
    /// it; the cost of that is a headline which knows nothing about what the deep pass found,
    /// and this is what stops the headline claiming more than it checked.
    /// </remarks>
    public int InferredCount { get; init; }

    /// <summary>The worst of those, across both readings.</summary>
    public Severity WorstInferred { get; init; } = Severity.Info;

    /// <summary>
    /// What the deep pass added, in a sentence, for display beside the score.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Beside the number, not below it.</b> The dependency caveat established this: the
    /// caveat moved into the verdict card and the number stayed where it was, because anything
    /// four cards down is invisible to a screenshot. Null when the deep pass added nothing that
    /// carries weight, on the same principle - a line that appears on every report stops being
    /// read.
    /// </para>
    /// <para>
    /// <b>It does not tell the reader their model might be the weak one.</b> An earlier wording
    /// explained the rule by saying that what an AI reports varies with which one you use. True,
    /// and the wrong thing to print: it ranks the reader's setup inside their own report, tells
    /// somebody running a free local model that theirs is the lesser answer, and puts the doubt
    /// on the whole document rather than on the finding it belongs to. Which model answered is
    /// already on the receipt for anyone comparing two reports, and that is where it belongs.
    /// </para>
    /// <para>
    /// What is said instead is what the reader can act on: these are suggestions rather than
    /// counted problems, every one quotes the code behind it so it can be judged rather than
    /// trusted, and the score is the part that means the same thing in every report. That is
    /// honest about the difference without inviting anybody to discount the tool over it.
    /// </para>
    /// </remarks>
    public string? InferredSummary => InferredCount == 0
        ? null
        : $"The AI also raised {InferredCount} "
          + $"{(InferredCount == 1 ? "point" : "points")} worth a look, the most serious rated "
          + $"{WorstInferred}. {(InferredCount == 1 ? "It is" : "They are")} listed below as "
          + "suggestions rather than counted problems, and each one quotes the code behind it so "
          + "you can judge it for yourself. The score comes from the checks alone, so it means "
          + "the same thing in every report.";

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

    /// <summary>
    /// Short label for the band, for display next to the score.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The top band is qualified when something was accounted for, and that qualification is
    /// the point. Scanning a cleaner and stating it has a reason to read browser cookies
    /// correctly produces 100/100, because the arithmetic genuinely has nothing left to count.
    /// Labelled "no known issues found", that headline is a screenshot claiming a clean bill of
    /// health for an application with six critical behaviours in it, all of them still listed
    /// further down where the screenshot does not reach. The number can stay honest and the
    /// label still overreach, so the label says what the number rests on.
    /// </para>
    /// <para>
    /// <b>Inferred findings qualify it for the same reason and take precedence.</b> The score
    /// counts deterministic findings only, so an application whose rules found nothing scores at
    /// the top however much the deep pass reported. Left as "no known issues found", the one
    /// case where the deep pass earns its keep - a real problem no pattern could express - would
    /// be published under a clean headline. Only the top band needs this: every band below it
    /// already says there is something to look at.
    /// </para>
    /// </remarks>
    public string BandLabel => Band switch
    {
        ScoreBand.CriticalIssues => "Critical issues",
        ScoreBand.SeriousIssues => "Serious issues",
        ScoreBand.NeedsWork => "Needs work",
        ScoreBand.NoKnownIssues => InferredCount > 0
            ? $"Nothing from the checks · {InferredCount} AI suggestions to review"
            : Advice == InstallAdvice.ConsistentWithStatedPurpose
                ? "Nothing beyond what you accounted for"
                : "No known issues found",
        ScoreBand.InsufficientCoverage => "Could not analyse",
        _ => "Unknown",
    };
}
