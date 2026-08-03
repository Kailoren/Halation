namespace VibeCheck.Core.Model;

/// <summary>
/// Who is reading the report, and therefore which question it answers.
/// </summary>
/// <remarks>
/// Two questions with two honest answers rather than one result in two voices: a private key in
/// the bundle is the worst thing in the report for whoever ships it and nearly irrelevant to
/// whoever runs it. The condition attached is that the headline must say which question it
/// answered, because a number that silently changes meaning with a setting is worse than either
/// number alone.
/// </remarks>
public enum Audience
{
    /// <summary>
    /// Someone deciding whether the application they built is fit to ship. Wants the rule
    /// identifier, the CVE, and the fix.
    /// </summary>
    Developer,

    /// <summary>
    /// Someone deciding whether to run an application they obtained. Wants to know what it
    /// could do to them and what they can do about it, and is not served by a CWE number.
    /// </summary>
    EndUser,
}

/// <summary>Wording that depends on who is asking.</summary>
public static class AudienceText
{
    /// <summary>
    /// The question the score answers, shown directly beneath it. Without this the same
    /// artifact showing two different numbers reads as a bug rather than as two answers.
    /// </summary>
    public static string ScoreCaption(this Audience audience) => audience switch
    {
        Audience.Developer => "Risk in shipping this application",
        Audience.EndUser => "Risk to you in running this application",
        _ => "Risk",
    };

    public static string Label(this Audience audience) => audience switch
    {
        Audience.Developer => "Developer",
        Audience.EndUser => "End user",
        _ => "Unknown",
    };
}
