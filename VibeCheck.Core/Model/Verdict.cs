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
    /// Which reader this verdict was calculated for, and therefore which question
    /// <see cref="Score"/> answers.
    /// </summary>
    public required Audience Audience { get; init; }

    /// <summary>
    /// The question the number answers, for display immediately beneath it.
    /// </summary>
    /// <remarks>
    /// Not optional furniture. The same artifact scores differently for the person shipping
    /// it and the person running it, because a leaked key ruins the first reader's day and
    /// none of the second's. An unlabelled number that changes with a setting is worse than
    /// either number on its own, so no display path should render <see cref="ScoreDisplay"/>
    /// without this beside it.
    /// </remarks>
    public string ScoreCaption => Audience.ScoreCaption();

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
