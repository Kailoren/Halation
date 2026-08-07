namespace Halation.Core.Model;

/// <summary>
/// What kind of application this was said to be, which decides how surprising each observed
/// capability is.
/// </summary>
/// <remarks>
/// <para>
/// <b>This does not account for anything, and that is the whole design.</b> It changes how the
/// question about an observed capability reads; it never decides the answer, never suppresses a
/// finding and never reaches <see cref="DeclaredPurpose"/> on its own. Every capability is still
/// affirmed one at a time and still printed back verbatim. A label that quietly waved behaviour
/// through would be the bypass-with-extra-steps that <see cref="Capability"/> warns against, and
/// picking a flattering one off a list is easy and deniable in a way that affirming a specific
/// observed behaviour is not.
/// </para>
/// <para>
/// The list is bounded by the capabilities rather than by the kinds of software in the world,
/// which is what stops it growing without end. There are seven capabilities, so there are seven
/// answers worth distinguishing, and a kind that expects none of them is a legitimate answer
/// rather than a gap.
/// </para>
/// </remarks>
public enum ApplicationKind
{
    /// <summary>
    /// Nothing has been said. The default, and the strict reading.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="General"/>, which is somebody answering the question. A missing
    /// answer must never read as a benign one: the same rule that makes a missing audience file
    /// mean "not asked yet" rather than a silent default.
    /// </remarks>
    Unstated,

    /// <summary>Ordinary software with no special reason for any of the capabilities.</summary>
    General,

    /// <summary>
    /// Software whose job is inspecting or defending a system.
    /// </summary>
    /// <remarks>
    /// <b>Expects nothing, deliberately.</b> Ali's call, 2026-08-06: it is the most flattering
    /// label on the list and it plausibly reaches cookies, saved passwords and wallet files all
    /// at once, which would make it the broadest excuse available. So it earns no blanket
    /// expectation and every capability is asked in the strict framing, one at a time. A security
    /// tool with a real reason can still affirm each one, and the report will say which.
    /// </remarks>
    SecurityTool,

    /// <summary>A cleaner, a privacy tool, or anything that tidies what a browser leaves behind.</summary>
    CleanerOrPrivacy,

    /// <summary>A password manager, or a tool that imports from a browser's saved logins.</summary>
    PasswordManager,

    /// <summary>A cryptocurrency wallet or a portfolio tracker.</summary>
    CryptoWallet,

    /// <summary>A tool built around a desktop chat client.</summary>
    ChatTool,

    /// <summary>Something that runs in the background, monitors, or updates itself.</summary>
    BackgroundUtility,
}

/// <summary>How a kind is named and what it makes unsurprising.</summary>
public static class ApplicationKinds
{
    /// <summary>The kind as a reader picks it off a list.</summary>
    public static string Humanise(this ApplicationKind kind) => kind switch
    {
        ApplicationKind.General => "General application",
        ApplicationKind.SecurityTool => "Security tool",
        ApplicationKind.CleanerOrPrivacy => "Cleaner or privacy tool",
        ApplicationKind.PasswordManager => "Password manager",
        ApplicationKind.CryptoWallet => "Cryptocurrency wallet",
        ApplicationKind.ChatTool => "Chat client tool",
        ApplicationKind.BackgroundUtility => "Background utility or updater",
        _ => "Not stated",
    };

    /// <summary>
    /// The kind as it reads inside a sentence about the application.
    /// </summary>
    public static string InSentence(this ApplicationKind kind) => kind switch
    {
        ApplicationKind.General => "a general application",
        ApplicationKind.SecurityTool => "a security tool",
        ApplicationKind.CleanerOrPrivacy => "a cleaner or privacy tool",
        ApplicationKind.PasswordManager => "a password manager",
        ApplicationKind.CryptoWallet => "a cryptocurrency wallet",
        ApplicationKind.ChatTool => "a chat client tool",
        ApplicationKind.BackgroundUtility => "a background utility",
        _ => "this application",
    };

    /// <summary>
    /// Capabilities that are unremarkable for this kind of application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only ever used to soften the <i>wording</i> of a question. Nothing here excuses anything:
    /// the reader still affirms each capability individually, and an unanswered one is still
    /// counted strictly.
    /// </para>
    /// <para>
    /// <see cref="ApplicationKind.SecurityTool"/> is empty on purpose, see its own remarks.
    /// <see cref="ApplicationKind.General"/> is empty because that is what answering "general"
    /// means, and <see cref="ApplicationKind.Unstated"/> because nobody has answered at all.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<Capability> Expects(this ApplicationKind kind) => kind switch
    {
        ApplicationKind.CleanerOrPrivacy => Set(Capability.BrowserCookies),
        ApplicationKind.PasswordManager => Set(Capability.BrowserCredentials),
        ApplicationKind.CryptoWallet => Set(
            Capability.CryptocurrencyWallets, Capability.ClipboardMonitoring),
        ApplicationKind.ChatTool => Set(Capability.ChatTokens),
        ApplicationKind.BackgroundUtility => Set(
            Capability.StartsWithWindows, Capability.DownloadsAndRunsCode),
        _ => Set(),
    };

    private static IReadOnlySet<Capability> Set(params Capability[] capabilities) =>
        new HashSet<Capability>(capabilities);

    /// <summary>Whether this capability is unremarkable for an application of this kind.</summary>
    public static bool Expects(this ApplicationKind kind, Capability capability) =>
        kind.Expects().Contains(capability);

    /// <summary>
    /// The question to put to the reader about one observed capability.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Phrased against what they said the application is, because "does it have a reason to?" is
    /// a much easier question to answer well when the reader is told whether the answer is
    /// usually yes. The unsurprising case still asks: an updater that starts with Windows is
    /// ordinary, and an updater that starts with Windows <i>and</i> reads wallet files is not,
    /// so the affirmation is worth having on the record either way.
    /// </para>
    /// <para>
    /// The surprising case names what would normally have this instead, which is the sentence
    /// that turns a vague worry into something checkable.
    /// </para>
    /// </remarks>
    public static string Question(this ApplicationKind kind, Capability capability) =>
        $"{capability.Statement()} {kind.Context(capability)} {Asked}";

    /// <summary>The question itself, phrased once so nothing can ask it differently.</summary>
    public const string Asked = "Does this one have a reason to?";

    /// <summary>
    /// How the kind is asked for, which is not the same question for the two readers.
    /// </summary>
    /// <remarks>
    /// A developer is describing what they built. Somebody checking a download is describing
    /// <i>what it claims to be</i>, which they know from wherever they got it. The gap between
    /// that claim and what the scan observed is the whole reason the question is worth asking
    /// of them. Wording it as "what kind of application is it" invites the honest answer
    /// "I don't know, that's why I'm scanning it", and loses the comparison.
    /// </remarks>
    public static string Prompt(Audience audience) => audience == Audience.EndUser
        ? "What is this supposed to be?"
        : "What kind of application is it?";

    /// <summary>The sentence under the prompt, for the same reason.</summary>
    public static string PromptNote(Audience audience) => audience == Audience.EndUser
        ? "Say what it is sold or described as, not what you think it does. VibeCheck compares "
          + "that against what it actually found: an application that says it is one thing and "
          + "behaves like another is the case most worth catching. Optional, and whatever you "
          + "pick is printed in the report."
        : "Optional. Leaving it blank is the strict reading: every capability found is still "
          + "reported, and every question is still asked, just without knowing what would be "
          + "normal here. Whatever you pick is printed in the report.";

    /// <summary>
    /// The middle sentence: whether this is surprising, given what was declared.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Question"/> because the window lays the three parts out itself
    /// and the export writes them as a sentence. Composed here rather than in either, so the two
    /// cannot word the same question differently.
    /// </remarks>
    public static string Context(this ApplicationKind kind, Capability capability)
    {
        if (kind.Expects(capability))
        {
            // Still asked. An updater that starts with Windows is ordinary; one that starts with
            // Windows and reads wallet files is not, so the affirmation is worth having either way.
            return $"That is normal for {kind.InSentence()}.";
        }

        return kind is ApplicationKind.Unstated
            ? $"That would be expected of {capability.ExpectedOf()}, and is unusual in anything else."
            : $"That is not usual for {kind.InSentence()}, and would be expected of "
              + $"{capability.ExpectedOf()}.";
    }
}
