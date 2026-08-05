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
