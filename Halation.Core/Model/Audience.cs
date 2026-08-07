namespace VibeCheck.Core.Model;

/// <summary>
/// Who is reading the report, and therefore which question it answers.
/// </summary>
/// <remarks>
/// Two questions with two honest answers rather than one result in two voices: a private key in
/// the bundle is the worst thing in the report for whoever ships it and nearly irrelevant to
/// whoever runs it. That governs which findings are shown, how they are worded, what can be done
/// about them and what order they come in.
///
/// <para>
/// It does not govern the headline number, which is the worse of the two readings and the same
/// in both reports. Two numbers on one artifact invited the report to be shopped: scan your own
/// work, switch to the reader it treats more kindly, screenshot that. See
/// <see cref="Scoring.ScoreCalculator"/>.
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
    /// How a reading is named where both are quoted, as in the account under the score.
    /// </summary>
    public static string Reading(this Audience audience) => audience switch
    {
        Audience.Developer => "as a question about shipping this",
        Audience.EndUser => "as a question about running it",
        _ => "as asked",
    };

    public static string Label(this Audience audience) => audience switch
    {
        Audience.Developer => "Developer",
        Audience.EndUser => "End user",
        _ => "Unknown",
    };
}
