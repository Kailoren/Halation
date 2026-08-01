using System.Text.RegularExpressions;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Behaviour that endangers the person installing the application.
/// </summary>
/// <remarks>
/// <para>
/// This is the only category permitted to advise against installation, and the rules are
/// held to a higher precision bar than the rest of the catalog because of it. Every rule
/// here matches a specific artefact of credential theft rather than a general capability:
/// the literal path of a browser password database, a wallet file, a token store.
/// </para>
/// <para>
/// The distinction from the rest of the catalog is who is harmed. A leaked API key is a
/// critical problem for the developer whose key it is. Code that reads the user's saved
/// browser passwords is a problem for the person who double-clicks the installer, and that
/// is the only thing worth interrupting them over.
/// </para>
/// <para>
/// Legitimate software does occasionally touch these paths, chiefly password managers and
/// browser import features. The findings are worded to say what was observed rather than to
/// assert intent, so a user with an actual password manager can recognise the explanation.
/// </para>
/// </remarks>
public static class MaliciousBehaviourRules
{
    /// <inheritdoc cref="SecretRules.All"/>
    public static IReadOnlyList<IRule> All =>
    [
        BrowserCredentialAccess,
        BrowserCookieTheft,
        CryptocurrencyWalletAccess,
        ChatTokenHarvesting,
        ClipboardAddressSwapping,
        PersistenceMechanism,
    ];

    private static PatternRule BrowserCredentialAccess { get; } = new()
    {
        Id = "VC-MAL-001",
        Title = "Application reads saved browser passwords",
        Severity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application references the file where a web browser stores saved passwords. "
            + "Reading it, together with the local decryption key, recovers every password the "
            + "user has saved in that browser in plaintext. This is the defining behaviour of "
            + "credential-stealing malware.",
        Remediation =
            "Do not run this application unless it is a password manager or browser import tool "
            + "from a publisher you already trust, and that is specifically why you installed it. "
            + "If it is anything else, treat the machine as at risk and change your passwords from "
            + "a different device.",
        Pattern = PatternRule.Compile(
            """
            (?:Google[\\/]Chrome[\\/]User\s?Data[^"'\r\n]{0,60}?Login\s?Data
            |Microsoft[\\/]Edge[\\/]User\s?Data[^"'\r\n]{0,60}?Login\s?Data
            |Mozilla[\\/]Firefox[\\/]Profiles[^"'\r\n]{0,60}?(?:logins\.json|key[34]\.db)
            |["']Login\s?Data["']
            |os_crypt[^"'\r\n]{0,40}encrypted_key)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule BrowserCookieTheft { get; } = new()
    {
        Id = "VC-MAL-002",
        Title = "Application reads browser session cookies",
        Severity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application references a browser's cookie database. Session cookies are "
            + "sufficient to sign in as the user without their password, and they bypass "
            + "two-factor authentication because the second factor was already satisfied when the "
            + "session was created.",
        Remediation =
            "Do not run this application. If it has already been run, sign out of your accounts "
            + "everywhere to invalidate existing sessions, then change your passwords from a "
            + "different device.",
        Pattern = PatternRule.Compile(
            """
            (?:User\s?Data[\\/][^"'\r\n]{0,40}?[\\/]Network[\\/]Cookies
            |["']Cookies["']\s*\)[^;\r\n]{0,40}?(?:sqlite|Connection)
            |cookies\.sqlite
            |encrypted_value[^;\r\n]{0,40}?cookies)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule CryptocurrencyWalletAccess { get; } = new()
    {
        Id = "VC-MAL-003",
        Title = "Application reads cryptocurrency wallet files",
        Severity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application references local cryptocurrency wallet storage. These files contain "
            + "the private keys controlling the user's funds, and transfers made with a stolen key "
            + "cannot be reversed.",
        Remediation =
            "Do not run this application. If it has already been run, move your funds to a new "
            + "wallet created on a machine you know to be clean.",
        Pattern = PatternRule.Compile(
            """
            (?:wallet\.dat
            |Ethereum[\\/]keystore
            |Exodus[\\/]exodus\.wallet
            |Electrum[\\/]wallets
            |nkbihfbeogaeaoehlefnkodbefgpgknn
            |MetaMask[\\/][^"'\r\n]{0,40}?\.log)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule ChatTokenHarvesting { get; } = new()
    {
        Id = "VC-MAL-004",
        Title = "Application harvests chat client authentication tokens",
        Severity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application reads the local storage of a desktop chat client, where the "
            + "authentication token is kept. That token allows an attacker to act as the user "
            + "without their password, and is routinely used to spread the same malware to their "
            + "contacts.",
        Remediation =
            "Do not run this application. If it has already been run, change your password to "
            + "invalidate existing tokens and warn your contacts about messages sent from your account.",
        Pattern = PatternRule.Compile(
            """
            (?:discord[\\/](?:Local\s?Storage|leveldb)
            |discordcanary|discordptb)
            [^;\r\n]{0,80}?(?:token|\.ldb|leveldb)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule ClipboardAddressSwapping { get; } = new()
    {
        Id = "VC-MAL-005",
        Title = "Application monitors the clipboard for wallet addresses",
        Severity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application watches the clipboard and matches cryptocurrency address patterns. "
            + "This is the signature of clipboard-hijacking malware, which silently substitutes "
            + "the attacker's address when the user copies one to make a payment.",
        Remediation =
            "Do not run this application. Verify the full destination address on the receiving "
            + "device before confirming any transfer made from this machine.",
        Pattern = PatternRule.Compile(
            """
            (?:clipboard|Clipboard\.(?:GetText|SetText)|pyperclip|clipboardy)
            [^;\r\n]{0,120}?
            (?:0x\[a-fA-F0-9\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1\[a-z0-9\]|\bbitcoin\b|\bethereum\b)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    /// <summary>
    /// Auto-start persistence. Reported but not blocking: ordinary installers legitimately
    /// register startup entries, so on its own this is context rather than proof.
    /// </summary>
    private static PatternRule PersistenceMechanism { get; } = new()
    {
        Id = "VC-MAL-006",
        Title = "Application configures itself to run at startup",
        Severity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application writes an auto-start entry, so it runs every time the user signs in. "
            + "This is normal for background utilities and updaters, and also how malware survives "
            + "a reboot. Judge it against whether the application has a reason to run continuously.",
        Remediation =
            "If persistent startup is not expected for this kind of application, treat it as "
            + "suspicious and review the other findings in this report together with it.",
        Pattern = PatternRule.Compile(
            """
            (?:CurrentVersion[\\/]+Run
            |Start\s?Menu[\\/][^"'\r\n]{0,40}?Startup
            |schtasks[^;\r\n]{0,40}?/create
            |RegisterTaskDefinition)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };
}
