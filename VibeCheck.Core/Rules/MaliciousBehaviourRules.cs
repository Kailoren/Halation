using System.Text.RegularExpressions;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Behaviour that endangers the person installing the application.
/// </summary>
/// <remarks>
/// The only category permitted to advise against installation, so every rule matches a
/// specific artefact of credential theft rather than a capability: the literal path of a
/// browser password database, a wallet file, a token store. What separates these from the rest
/// of the catalog is who is harmed, since a leaked key hurts the developer and a password
/// stealer hurts whoever double-clicked. Findings say what was observed rather than asserting
/// intent, because password managers touch these paths legitimately.
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
        DownloadsAndRuns,
        LivesOffTheLand,
    ];

    /// <summary>
    /// A remote fetch of any kind. Half of what makes an execution call a dropper.
    /// </summary>
    private static readonly Regex Fetches = PatternRule.Compile(
        """
        https?://
        |HttpClient|WebClient|HttpWebRequest|DownloadFile|DownloadData|DownloadString
        |urlretrieve|requests\.(?:get|post)|urlopen
        |fetch\s*\(|axios|node-fetch|https?\.get\s*\(
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// The other half: the fetched bytes landing somewhere they can be run from. Temporary
    /// directories are in here rather than in the execution pattern because writing to one is
    /// what turns a download into a file on the machine.
    /// </summary>
    private static readonly Regex WritesAFile = PatternRule.Compile(
        """
        WriteAllBytes|FileStream|CopyToAsync|GetTempPath|GetTempFileName
        |createWriteStream|writeFileSync|os\.tmpdir|app\.getPath\s*\(\s*["']temp
        |copyfileobj|tempfile\.|NamedTemporaryFile
        |open\s*\([^)\r\n]{0,80}["']wb["']
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// Whether the file around a match shows the rest of a download-then-run sequence. Done in
    /// code rather than as one regex spanning both halves: the two calls are routinely tens of
    /// lines apart, and a pattern elastic enough to reach across that is both slow and prone to
    /// matching a fetch in one method against an execution in an unrelated one.
    /// </summary>
    private static bool NoDownloadNearby(RuleContext context) =>
        !Fetches.IsMatch(context.Content) || !WritesAFile.IsMatch(context.Content);

    /// <summary>
    /// Constructs that only appear in a regular expression, never in a command.
    /// </summary>
    private static readonly Regex RegexSyntax = PatternRule.Compile(
        @"\(\?[:i]|\[\^|\\[sbdwSBDW]|\.\*");

    /// <summary>
    /// Whether the matched line is a pattern that describes a command rather than a line that
    /// runs one.
    /// </summary>
    /// <remarks>
    /// The patterns in this file are string literals that survive decompilation, so scanning
    /// VibeCheck's own build made the rules match their own definitions and advise against
    /// installing the scanner. Any application shipping pattern-based detection has the same
    /// shape.
    /// </remarks>
    private static bool LooksLikeAPattern(Match match, RuleContext context)
    {
        // A window around the match rather than the line it sits on. A minified bundle is one
        // line of several hundred kilobytes, and testing all of it would let a regular
        // expression anywhere in the file explain away a match anywhere else, which quietly
        // turned this guard into a way of never reporting a bundled application at all.
        const int reach = 120;

        var content = context.Content;
        var start = Math.Max(0, match.Index - reach);
        var end = Math.Min(content.Length, match.Index + match.Length + reach);

        return RegexSyntax.IsMatch(content[start..end]);
    }

    private static PatternRule BrowserCredentialAccess { get; } = new()
    {
        Id = "VC-MAL-001",
        Title = "Application reads saved browser passwords",
        Severity = Severity.Critical,
        UserSeverity = Severity.Critical,
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
        UserDescription =
            "This application contains code that reads the passwords saved in your web browser. "
            + "There is no legitimate reason for an ordinary application to do this. If you have "
            + "run it already, treat your saved passwords as known to somebody else.",
        UserRemediation =
            "Do not run this application. If you already have, change the passwords saved in your "
            + "browser, starting with email and banking, and turn on two-factor authentication "
            + "where you can.",
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
        UserSeverity = Severity.Critical,
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
        UserDescription =
            "This application contains code that reads your browser session cookies. Those are "
            + "what keep you signed in, so taking them lets somebody else use your accounts without "
            + "ever needing your password.",
        UserRemediation =
            "Do not run this application. If you already have, sign out of everything on that "
            + "browser to invalidate the sessions, then change your passwords.",
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
        UserSeverity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application references local cryptocurrency wallet storage. These files contain "
            + "the private keys controlling the user's funds, and transfers made with a stolen key "
            + "cannot be reversed.",
        Remediation =
            "Do not run this application. If it has already been run, move your funds to a new "
            + "wallet created on a machine you know to be clean.",
        UserDescription =
            "This application contains code that goes looking for cryptocurrency wallet files on "
            + "your computer. Those files are the money. There is no legitimate reason for an "
            + "unrelated application to read them.",
        UserRemediation =
            "Do not run this application. If you already have, move your funds to a new wallet "
            + "from a different machine.",
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
        UserSeverity = Severity.Critical,
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
        UserDescription =
            "This application contains code that takes the sign-in tokens from your chat "
            + "programs. Those tokens let someone use your account, read your messages, and message "
            + "your contacts as you.",
        UserRemediation =
            "Do not run this application. If you already have, log out of every session in those "
            + "chat apps and change the passwords.",
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
        UserSeverity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application watches the clipboard and matches cryptocurrency address patterns. "
            + "This is the signature of clipboard-hijacking malware, which silently substitutes "
            + "the attacker's address when the user copies one to make a payment.",
        Remediation =
            "Do not run this application. Verify the full destination address on the receiving "
            + "device before confirming any transfer made from this machine.",
        UserDescription =
            "This application watches your clipboard for cryptocurrency addresses. This is the "
            + "pattern used to swap the address you copied for the attacker's own, so that a payment "
            + "you thought you were sending to yourself goes to them instead.",
        UserRemediation =
            "Do not run this application. If you already have, check the address carefully on any "
            + "recent transfer.",
        Pattern = PatternRule.Compile(
            """
            (?:clipboard|Clipboard\.(?:GetText|SetText)|pyperclip|clipboardy)
            [^;\r\n]{0,120}?
            (?:0x\[a-fA-F0-9\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1\[a-z0-9\]|\bbitcoin\b|\bethereum\b)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    /// <summary>
    /// Fetch something, put it on disk, run it.
    /// </summary>
    /// <remarks>
    /// <b>A capability, not a defect.</b> This is how every self-updating application works,
    /// and it was rated High: one of those caps the score at 69 and relabels a correct program
    /// as having serious issues, which is how a scanner teaches people to stop reading it. It
    /// is still worth reporting, and to somebody deciding whether to run a download it may be
    /// the most useful line in the report, so it is listed and explained rather than scored.
    /// The unambiguous version of this shape is VC-MAL-008, which stays a finding and blocks.
    /// </remarks>
    private static PatternRule DownloadsAndRuns { get; } = new()
    {
        Id = "VC-MAL-007",
        Title = "Can download and run a program",
        IsCapability = true,

        // Info on both, so that even if this were ever counted it could not move a number.
        // The section it lives in is kept out of the arithmetic; this is the second lock.
        Severity = Severity.Info,
        UserSeverity = Severity.Info,
        Category = FindingCategory.CodeSafety,
        Description =
            "This file fetches something over the network, writes it to disk, and executes a "
            + "program, which is how a self-updating application works. Worth knowing rather "
            + "than worth fixing: what the application does after installation is decided by "
            + "whatever the server sends, so it is not fully described by a scan of what shipped. "
            + "In a bundled or minified file the three calls may belong to three different "
            + "libraries rather than to one sequence, because a bundle is the smallest unit "
            + "there is to judge them in.",
        Remediation =
            "Nothing to fix if this is your updater. Worth confirming it verifies what it "
            + "downloaded before running it: a signature checked against a key shipped in the "
            + "application, rather than a hash served from the same place as the file.",
        UserDescription =
            "This application can download a program and run it. That is how anything which "
            + "updates itself works, so it is normal rather than alarming. It does mean what "
            + "this application will do on your machine tomorrow is decided by whatever it "
            + "downloads, which is not something a scan of it today can tell you.",
        UserRemediation =
            "Judge it against whether this application has a reason to update itself. If it has "
            + "no such reason, downloading and running a program is worth asking about.",
        // No bare "\.exec\s*\(": in JavaScript that is how you run a regular expression, and
        // matching it reported a base64 data-URL check and a difficulty-band parser as programs
        // being launched. Both were found by running this rule over applications known to be
        // honest, which is the only way that class of mistake shows up. The named process calls
        // below are unambiguous, and a file destructuring exec out of child_process still
        // matches on the import.
        Pattern = PatternRule.Compile(
            """
            (?:Process\.Start|ProcessStartInfo|ShellExecute(?:Ex)?|CreateProcess
            |child_process|\bexecFile(?:Sync)?\s*\(|\bexecSync\s*\(|\bspawn(?:Sync)?\s*\(
            |subprocess\.(?:Popen|call|run|check_output)|os\.system|os\.startfile
            |Runtime\.getRuntime\(\)\.exec)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) =>
            NoDownloadNearby(context) || LooksLikeAPattern(match, context),
    };

    /// <summary>
    /// Execution routed through a Windows binary that exists for something else.
    /// </summary>
    /// <remarks>
    /// Blocking, and held to the same bar as the credential rules: each alternative is a named
    /// technique rather than a capability. An application with its own HTTP client has no reason
    /// to download through <c>certutil</c>, and nothing legitimate pipes a web response into a
    /// shell. <c>powershell -EncodedCommand</c> is deliberately absent, being something real
    /// installers do to get around quoting.
    /// </remarks>
    private static PatternRule LivesOffTheLand { get; } = new()
    {
        Id = "VC-MAL-008",
        Title = "Runs downloaded content through a Windows utility",
        Severity = Severity.Critical,
        UserSeverity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        IsBlocking = true,
        Description =
            "The application invokes a built-in Windows tool to fetch or execute remote content: "
            + "downloading with certutil or bitsadmin, or handing a URL to mshta, regsvr32 or a "
            + "shell. These are living-off-the-land techniques, used because the tools are "
            + "already trusted on the machine and the traffic does not come from the "
            + "application. Software that needs a file downloads it with its own HTTP client.",
        Remediation =
            "Do not ship this. Download with the application's own HTTP client over TLS and "
            + "verify what arrives. If this code is not yours, treat the build as compromised.",
        UserDescription =
            "This application uses built-in Windows tools to pull code off the internet and run "
            + "it. This is a technique for getting code onto a machine without it looking like a "
            + "download, and ordinary software has no reason to work this way.",
        UserRemediation =
            "Do not run this application. If you already have, treat the machine as needing a "
            + "proper malware scan by something built for it, and change passwords from a "
            + "different device.",
        Pattern = PatternRule.Compile(
            """
            (?:certutil[^\r\n]{0,60}?-(?:urlcache|decode)
            |bitsadmin[^\r\n]{0,40}?/transfer
            |mshta[^\r\n]{0,20}?https?:
            |regsvr32[^\r\n]{0,40}?/i:\s*https?:
            |(?:Invoke-Expression|\biex\b)[^\r\n]{0,80}?(?:DownloadString|Invoke-WebRequest|\birm\b|\bcurl\b|\bwget\b)
            |(?:curl|wget)[^\r\n|]{0,120}?\|\s*(?:ba)?sh\b)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
        Ignore = LooksLikeAPattern,
    };

    /// <summary>
    /// Auto-start persistence.
    /// </summary>
    /// <remarks>
    /// <b>A capability, not a defect.</b> Ordinary installers register startup entries and so
    /// does malware, which makes this context rather than evidence. Charging a Medium for it
    /// meant every background utility lost a band of score for working the way background
    /// utilities work.
    /// </remarks>
    private static PatternRule PersistenceMechanism { get; } = new()
    {
        Id = "VC-MAL-006",
        Title = "Can start itself when you sign in",
        IsCapability = true,
        Severity = Severity.Info,
        UserSeverity = Severity.Info,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application writes an auto-start entry, so it runs every time the user signs in. "
            + "This is normal for background utilities and updaters, and also how malware survives "
            + "a reboot. Judge it against whether the application has a reason to run continuously.",
        Remediation =
            "If persistent startup is not expected for this kind of application, treat it as "
            + "suspicious and review the other findings in this report together with it.",
        UserDescription =
            "The application sets itself to start automatically when you turn your computer on. "
            + "Plenty of ordinary software does this, but it means the app keeps running whether or "
            + "not you asked for it that day, so it is worth knowing it is there.",
        UserRemediation =
            "If you did not want this, look for a start with system setting in the app, or remove "
            + "it from your startup programs.",
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
