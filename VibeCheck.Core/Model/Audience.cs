namespace VibeCheck.Core.Model;

/// <summary>
/// Who is reading the report, and therefore which question it answers.
/// </summary>
/// <remarks>
/// <para>
/// These are two different questions with two different honest answers, not one result in
/// two voices. A private key baked into the bundle is the worst thing in the report for the
/// person shipping it, and very nearly irrelevant to the person running it, because the key
/// that is exposed belongs to the author rather than to them. Run the same severity past both
/// and one of them is reading a number that answers somebody else's question.
/// </para>
/// <para>
/// The honesty condition attached to this is that the headline must say which question it
/// answered. A number that silently changes meaning with a setting is worse than either
/// number alone.
/// </para>
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
