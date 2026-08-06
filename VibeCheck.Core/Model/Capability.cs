namespace VibeCheck.Core.Model;

/// <summary>
/// A power the application was observed to have, named so that a declared purpose can be
/// weighed against it.
/// </summary>
/// <remarks>
/// <para>
/// The problem this exists to solve: reading a browser's cookie database is the defining
/// behaviour of credential-stealing malware and also the defining behaviour of a cleaning
/// utility. Rated on the observation alone, VC-MAL-002 tells the author of a cleaner not to
/// install their own application, and a reader who meets that once learns to disregard the
/// banner. The observation is correct in both cases. What differs is whether the application
/// had a reason.
/// </para>
/// <para>
/// So findings that can be explained by what an application is for carry the power they
/// demonstrate rather than an implied verdict, and the question the report asks becomes
/// whether the application does more than its stated job requires. That question has an
/// answer; "is this dangerous" does not, absent context.
/// </para>
/// <para>
/// <b>Most rules carry nothing here, and that is the important half.</b> A leaked credential,
/// a vulnerable dependency, an injection sink and a living-off-the-land invocation are wrong
/// whatever the application is for. Leaving them untagged is what stops a declaration from
/// becoming a way to wave anything through: there has to be a tier no purpose reaches, or the
/// feature is a bypass with extra steps.
/// </para>
/// </remarks>
public enum Capability
{
    /// <summary>Reads the store where a browser keeps saved passwords.</summary>
    /// <remarks>Expected of password managers and browser import tools, and of nothing else.</remarks>
    BrowserCredentials,

    /// <summary>Reads a browser's cookie database.</summary>
    /// <remarks>
    /// Expected of cleaners, privacy tools and browser managers. The case this whole taxonomy
    /// was written for.
    /// </remarks>
    BrowserCookies,

    /// <summary>Reads local cryptocurrency wallet storage.</summary>
    /// <remarks>Expected of wallets, portfolio trackers and backup tools.</remarks>
    CryptocurrencyWallets,

    /// <summary>Reads the token store of a desktop chat client.</summary>
    /// <remarks>
    /// Expected of very little. Kept taggable rather than absolute because chat tooling does
    /// exist, but a purpose claiming it should be read sceptically.
    /// </remarks>
    ChatTokens,

    /// <summary>Watches the clipboard for cryptocurrency addresses.</summary>
    /// <remarks>Expected of wallets, which validate a pasted address for exactly this reason.</remarks>
    ClipboardMonitoring,

    /// <summary>Registers itself to run when the user signs in.</summary>
    /// <remarks>Expected of background utilities, updaters and anything that monitors.</remarks>
    StartsWithWindows,

    /// <summary>Fetches something, writes it to disk, and runs it.</summary>
    /// <remarks>Expected of anything that updates itself, which is most things.</remarks>
    DownloadsAndRunsCode,
}

/// <summary>How a capability is named where a reader will see it.</summary>
/// <remarks>
/// Here rather than in each renderer, on the same reasoning as
/// <see cref="FindingCategories"/>: the category display names existed in two places once and
/// drifted the same hour a category was added.
/// </remarks>
public static class Capabilities
{
    /// <summary>What the application can do, phrased for somebody deciding whether to run it.</summary>
    public static string Humanise(this Capability capability) => capability switch
    {
        Capability.BrowserCredentials => "Read your saved browser passwords",
        Capability.BrowserCookies => "Read your browser cookies",
        Capability.CryptocurrencyWallets => "Read your cryptocurrency wallet files",
        Capability.ChatTokens => "Read the sign-in tokens from your chat apps",
        Capability.ClipboardMonitoring => "Watch your clipboard for wallet addresses",
        Capability.StartsWithWindows => "Start itself when you sign in",
        Capability.DownloadsAndRunsCode => "Download a program and run it",
        _ => capability.ToString(),
    };

    /// <summary>What was observed, as a sentence about the application.</summary>
    public static string Statement(this Capability capability)
    {
        var phrase = capability.Humanise();

        return $"This application can {char.ToLowerInvariant(phrase[0])}{phrase[1..]}.";
    }

    /// <summary>
    /// How to hold this power safely, for a reader who has said they need it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The answer to "yes, it has a reason to" is not silence. This tool exists to help people
    /// build better applications, and somebody who has just confirmed they need a capability is
    /// at the one moment they will actually read advice about it. Saying nothing there wastes
    /// the only opening the report gets.
    /// </para>
    /// <para>
    /// <b>Bounded on purpose.</b> Seven capabilities, seven pieces of advice. The temptation is
    /// to enumerate correct usage per verb per kind of application, which does not converge:
    /// there is no end to the ways software can be built, and each entry would be a table to
    /// maintain forever and still incomplete. What generalises is the boundary of the
    /// affirmation - reading a thing is not sending it anywhere - and that is one sentence per
    /// capability rather than a matrix. Anything finer is a judgement about specific code, which
    /// is the deep pass's job and is already what it is asked for.
    /// </para>
    /// </remarks>
    public static string Safeguard(this Capability capability) => capability switch
    {
        Capability.BrowserCredentials =>
            "Having a reason to read the store accounts for reading it, not for what happens "
            + "next. Read through the platform's credential API rather than the file where you "
            + "can, take only the entry you were asked for, keep nothing in memory after the "
            + "operation, and never send any of it anywhere, including to your own servers.",

        Capability.BrowserCookies =>
            "Having a reason to read them accounts for reading them, not for sending them "
            + "anywhere. Open the database read-only unless deleting is the actual job, work on "
            + "a copy you delete afterwards rather than the browser's own file, and never "
            + "transmit cookie values off the machine. A session cookie is a signed-in session, "
            + "so anything that moves one is doing what a stealer does regardless of intent.",

        Capability.CryptocurrencyWallets =>
            "Having a reason to read wallet storage accounts for reading it, not for handling "
            + "key material. Read metadata rather than keys or seed phrases wherever the feature "
            + "allows, never write either to a log or a crash report, and never transmit them. "
            + "If the feature genuinely needs a key, ask the user each time instead of storing "
            + "what you were given.",

        Capability.ChatTokens =>
            "Having a reason to read a token store accounts for reading it, not for reusing the "
            + "token elsewhere. Use the client's own documented integration point if one exists, "
            + "since a token lifted from disk keeps working after the user signs out and is "
            + "invisible to them. Never log it and never send it anywhere but the service it "
            + "belongs to.",

        Capability.ClipboardMonitoring =>
            "Having a reason to watch the clipboard accounts for inspecting what is pasted, not "
            + "for reading it continuously. Look only while your own paste target has focus, "
            + "match the shape you need and discard everything else immediately, and never log "
            + "or transmit clipboard contents. A clipboard carries passwords and messages that "
            + "have nothing to do with your application.",

        Capability.StartsWithWindows =>
            "Having a reason to start with Windows accounts for starting, not for being hard to "
            + "stop. Register per user rather than machine-wide so no administrator rights are "
            + "needed, offer the switch inside your own settings rather than only in the "
            + "installer, and make sure removing the application removes the entry.",

        Capability.DownloadsAndRunsCode =>
            "Having a reason to update yourself accounts for fetching and running your own "
            + "builds, nothing else. Verify what you downloaded against a signature you can "
            + "check, not a hash served from the same place as the file, because whoever can "
            + "replace one can replace the other. Refuse to run anything that fails, follow "
            + "redirects by hand so every hop is checked, and never execute a path taken from "
            + "the server's reply.",

        _ => "Having a reason to do this accounts for doing it, not for what is done with the "
             + "result. Take the least you need, keep it no longer than the operation, and do "
             + "not send it anywhere the user did not ask you to.",
    };

    /// <summary>
    /// The kind of application a reasonable person would expect to have this, for the report to
    /// say when the declared purpose accounts for it.
    /// </summary>
    public static string ExpectedOf(this Capability capability) => capability switch
    {
        Capability.BrowserCredentials => "a password manager or a browser import tool",
        Capability.BrowserCookies => "a cleaner or a privacy tool",
        Capability.CryptocurrencyWallets => "a wallet or a portfolio tracker",
        Capability.ChatTokens => "a tool built around a chat client",
        Capability.ClipboardMonitoring => "a cryptocurrency wallet",
        Capability.StartsWithWindows => "a background utility or an updater",
        Capability.DownloadsAndRunsCode => "anything that updates itself",
        _ => "an application of some other kind",
    };
}
