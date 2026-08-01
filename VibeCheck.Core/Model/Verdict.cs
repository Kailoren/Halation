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

    /// <summary>Short label for the band, for display next to the score.</summary>
    public string BandLabel => Band switch
    {
        ScoreBand.DoNotInstall => "Do not install",
        ScoreBand.SeriousIssues => "Serious issues",
        ScoreBand.NeedsWork => "Needs work",
        ScoreBand.NoKnownIssues => "No known issues found",
        _ => "Unknown",
    };
}
