using System.Text.RegularExpressions;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Misconfiguration checks, weighted to the platforms AI code generators reach for.
/// </summary>
/// <remarks>
/// These are the defaults an assistant leaves open to make an example work. Individually
/// each looks like a development convenience; shipped, each is an unauthenticated path into
/// the application's data or the user's machine.
/// </remarks>
public static class ConfigurationRules
{
    /// <inheritdoc cref="SecretRules.All"/>
    public static IReadOnlyList<IRule> All =>
    [
        FirebaseOpenRules,
        ElectronNodeIntegration,
        ElectronRemoteContent,
        CorsWildcardWithCredentials,
        TlsVerificationDisabled,
        LegacyTlsForced,
        CleartextApiEndpoint,
        BindsToAllInterfaces,
        DebugModeEnabled,
    ];

    private static PatternRule FirebaseOpenRules { get; } = new()
    {
        Id = "VC-CFG-001",
        Title = "Firebase security rules allow unrestricted access",
        Severity = Severity.Critical,
        UserSeverity = Severity.High,
        Category = FindingCategory.Auth,
        Description =
            "The Firebase rules grant read or write access with a condition that is always true. "
            + "Anyone who extracts the project identifier from the application, which is public by "
            + "design, can read and modify the entire database.",
        Remediation =
            "Replace the blanket allow with rules that check request.auth and restrict each "
            + "collection to its owner. Test them with the Firebase rules simulator before shipping.",
        UserDescription =
            "The database behind this application is configured to let anyone read and write it, "
            + "with no check on who is asking. Anything you save through this app can be read, "
            + "changed, or deleted by any stranger who cares to look.",
        UserRemediation ="Do not put anything private into this application until the developer fixes it.",
        Pattern = PatternRule.Compile(
            """(?:allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true|"\.(?:read|write)"\s*:\s*true)""",
            RegexOptions.IgnoreCase),
        Reference = "https://firebase.google.com/docs/rules",
    };

    private static PatternRule ElectronNodeIntegration { get; } = new()
    {
        Id = "VC-CFG-002",
        Title = "Electron renderer has Node.js integration enabled",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application creates a browser window with nodeIntegration enabled. Any script "
            + "that runs in that window, including one injected through a cross-site scripting "
            + "flaw or loaded from a third party, gets full Node.js access: the filesystem, "
            + "process execution, and the network.",
        Remediation =
            "Set nodeIntegration to false and contextIsolation to true, then expose only the "
            + "specific operations the renderer needs through a preload script and contextBridge.",
        UserDescription =
            "This application displays web content with the safety barrier between that content "
            + "and your computer switched off. A page it loads, or an advert inside one, can reach "
            + "your files rather than staying in the window.",
        UserRemediation =
            "Be cautious about what you let this application load, and consider whether you need "
            + "it installed.",
        Pattern = PatternRule.Compile("""nodeIntegration\s*:\s*true""", RegexOptions.IgnoreCase),
        Languages = [SourceLanguage.JavaScript, SourceLanguage.TypeScript],
        Reference = "https://www.electronjs.org/docs/latest/tutorial/security",
    };

    private static PatternRule ElectronRemoteContent { get; } = new()
    {
        Id = "VC-CFG-003",
        Title = "Electron context isolation is disabled",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "Context isolation is turned off, so page scripts share a JavaScript context with the "
            + "application's preload code. A malicious page can then reach the privileged APIs the "
            + "preload script holds and escape the renderer sandbox.",
        Remediation =
            "Set contextIsolation to true, which is the default in current Electron, and pass data "
            + "across the boundary with contextBridge.exposeInMainWorld.",
        UserDescription =
            "The wall between web content and your computer has been taken down inside this "
            + "application. Content it displays can reach out to your machine instead of staying "
            + "inside the page.",
        UserRemediation =
            "Be cautious about what you let this application load, and consider whether you need "
            + "it installed.",
        Pattern = PatternRule.Compile("""contextIsolation\s*:\s*false""", RegexOptions.IgnoreCase),
        Languages = [SourceLanguage.JavaScript, SourceLanguage.TypeScript],
        Reference = "https://www.electronjs.org/docs/latest/tutorial/context-isolation",
    };

    private static PatternRule CorsWildcardWithCredentials { get; } = new()
    {
        Id = "VC-CFG-004",
        Title = "CORS allows any origin together with credentials",
        Severity = Severity.High,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.Network,
        Description =
            "The service accepts requests from any origin while also allowing credentials to be "
            + "sent. Any website a signed-in user visits can then make authenticated requests to "
            + "this API and read the responses.",
        Remediation =
            "Replace the wildcard with an explicit list of trusted origins. If credentials are "
            + "genuinely needed cross-origin, the origin must be named exactly.",
        UserDescription =
            "This application accepts requests from any website while still carrying your sign-in "
            + "with them. That means another site you happen to have open could quietly act as you "
            + "against this application.",
        UserRemediation ="Sign out of this application when you are not using it.",
        Pattern = PatternRule.Compile(
            """
            (?:origin\s*:\s*["']\*["'][^}]{0,200}?credentials\s*:\s*true
            |credentials\s*:\s*true[^}]{0,200}?origin\s*:\s*["']\*["']
            |Access-Control-Allow-Origin["']\s*,\s*["']\*["'][^;]{0,200}?Allow-Credentials)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace | RegexOptions.Singleline),
    };

    private static PatternRule TlsVerificationDisabled { get; } = new()
    {
        Id = "VC-CFG-005",
        Title = "TLS certificate verification is disabled",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.Network,
        Description =
            "The application accepts any TLS certificate without validating it. Encryption still "
            + "happens, but there is no longer any guarantee about who is on the other end, so "
            + "anyone positioned on the network can intercept and modify the traffic undetected.",
        Remediation =
            "Remove the override. If a self-signed certificate is genuinely required, pin that "
            + "specific certificate rather than disabling validation altogether.",
        UserDescription =
            "The application does not check that it is really talking to who it thinks it is "
            + "talking to. Anyone sharing your network, including public wifi, can read what it "
            + "sends and change what it receives without either of you noticing.",
        UserRemediation ="Avoid using this application on public or shared wifi.",
        Pattern = PatternRule.Compile(
            """
            (?:rejectUnauthorized\s*:\s*false
            |NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0
            |verify\s*=\s*False
            |ServerCertificateValidationCallback\s*(?:\+)?=\s*(?:\([^)]*\)\s*=>\s*true|delegate)
            |DangerousAcceptAnyServerCertificateValidator
            |InsecureSkipVerify\s*:\s*true)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule LegacyTlsForced { get; } = new()
    {
        Id = "VC-CFG-006",
        Title = "Application forces an obsolete TLS version",
        Severity = Severity.Medium,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.Network,
        Description =
            "The application explicitly selects TLS 1.0 or 1.1, or SSL 3.0. These are deprecated "
            + "and carry known weaknesses, and pinning to them prevents the platform from "
            + "negotiating something current.",
        Remediation =
            "Remove the explicit version and let the platform negotiate, which selects TLS 1.2 or "
            + "1.3 by default. Pin a minimum rather than an exact version if one is required.",
        UserDescription =
            "The application insists on an outdated method for securing its connection, one with "
            + "known weaknesses. Someone on the same network has a realistic path to reading what "
            + "it sends.",
        UserRemediation ="Avoid using this application on public or shared wifi.",
        Pattern = PatternRule.Compile(
            """
            (?:SecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b
            |SslProtocols\.(?:Ssl2|Ssl3|Tls|Tls11)\b
            |PROTOCOL_TLSv1(?:_1)?\b
            |["']TLSv1(?:\.1)?["']
            |minVersion\s*:\s*["']TLSv1(?:\.1)?["'])
            """,
            RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule CleartextApiEndpoint { get; } = new()
    {
        Id = "VC-CFG-007",
        Title = "Application calls an API over plain HTTP",
        Severity = Severity.Medium,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.Network,
        Description =
            "A remote endpoint is addressed over http rather than https, so the request and its "
            + "response travel unencrypted and can be read or altered in transit. Any credential "
            + "or token sent this way is exposed.",
        Remediation = "Use https for every remote endpoint.",
        UserDescription =
            "The application sends some of its traffic unencrypted. Anyone between you and the "
            + "other end, including whoever runs the wifi you are on, can read it and alter it.",
        UserRemediation ="Avoid entering anything sensitive into this application on public or shared wifi.",
        Pattern = PatternRule.Compile(
            """["'](http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[a-z0-9.\-]+\.[a-z]{2,}[^"']*)["']""",
            RegexOptions.IgnoreCase),
        Ignore = (match, context) =>
            // Namespace and schema URLs are identifiers, not network calls.
            match.Value.Contains("://www.w3.org", StringComparison.OrdinalIgnoreCase)
            || match.Value.Contains("://schemas.", StringComparison.OrdinalIgnoreCase)
            || match.Value.Contains("://xmlns.", StringComparison.OrdinalIgnoreCase)
            || match.Value.Contains(".xsd", StringComparison.OrdinalIgnoreCase)
            || match.Value.Contains(".dtd", StringComparison.OrdinalIgnoreCase)
            || IsPackageMetadata(match, context)
            || Heuristics.IsInLineComment(context, match.Index),
    };

    /// <summary>
    /// An npm manifest's own homepage, repository and issue URLs are frequently http, and
    /// none of them is a request the application makes.
    /// </summary>
    /// <remarks>
    /// Found scanning a real Electron installer: it vendors hundreds of dependency
    /// manifests, and six of them carried an http repository URL. That was enough to put a
    /// clean application in the "serious issues" band on nothing but package metadata, which
    /// is exactly the kind of confident wrong answer that makes a scanner not worth running.
    /// The suppression is keyed on the metadata fields rather than on the file, so an actual
    /// endpoint configured in a manifest is still reported.
    /// </remarks>
    private static bool IsPackageMetadata(Match match, RuleContext context)
    {
        var name = Path.GetFileName(context.File.RelativePath);

        if (!name.Equals("package.json", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return MetadataField.IsMatch(context.LineFor(match));
    }

    private static readonly Regex MetadataField = new(
        """
        "(?:homepage|repository|url|web|site|bugs|funding|author|maintainers|contributors|email|issues|docs|resolved|tarball)"\s*:
        """,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        PatternRule.MatchTimeout);

    /// <summary>
    /// Binding to every interface, which is what turns a local helper into a network service.
    /// </summary>
    /// <remarks>
    /// Reported as high severity but deliberately not blocking. Binding broadly is correct
    /// for a real server and wrong for a desktop application, and a regex cannot reliably
    /// establish whether the listener also requires authentication. The strongest claim in
    /// the report is reserved for findings that can be established with certainty.
    /// </remarks>
    private static PatternRule BindsToAllInterfaces { get; } = new()
    {
        Id = "VC-CFG-008",
        Title = "Service listens on every network interface",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.Network,
        Description =
            "The application opens a listening socket bound to 0.0.0.0, which accepts connections "
            + "from any machine that can reach the host rather than only from the local computer. "
            + "In a desktop application this usually exposes an internal helper service to the "
            + "user's entire network.",
        Remediation =
            "Bind to 127.0.0.1 for anything only the local machine should reach. If remote access "
            + "is intended, require authentication and document that the port is exposed.",
        UserDescription =
            "The application opens a door on your computer that is reachable from your whole "
            + "network rather than just from your own machine. On shared or public wifi, other "
            + "people on that network can connect to it.",
        UserRemediation ="Avoid running this application on public or shared networks.",
        Pattern = PatternRule.Compile(
            """
            (?:(?:host|hostname|address|bind|listen)\s*[:=]\s*["']0\.0\.0\.0["']
            |listen\s*\([^)]*["']0\.0\.0\.0["']
            |IPAddress\.Any
            |["']0\.0\.0\.0:\d+["'])
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule DebugModeEnabled { get; } = new()
    {
        Id = "VC-CFG-009",
        Title = "Debug mode enabled in shipped code",
        Severity = Severity.Medium,
        UserSeverity = Severity.Low,
        Category = FindingCategory.CodeSafety,
        Description =
            "A debug flag is switched on in code that ships. Debug modes commonly expose stack "
            + "traces, configuration, and interactive consoles to whoever triggers an error.",
        Remediation =
            "Drive the flag from configuration and default it to off, so a released build cannot "
            + "start in debug mode.",
        UserDescription =
            "The application was shipped with its diagnostic mode left on. It will report more "
            + "about its own workings than it should, which is untidy rather than dangerous for "
            + "you.",
        Pattern = PatternRule.Compile(
            """(?:DEBUG\s*[:=]\s*True|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)""",
            RegexOptions.IgnoreCase),
        Ignore = (match, context) =>
            Heuristics.IsGeneratedCode(context.File.RelativePath)
            || Heuristics.IsTestOrExampleFile(context.File.RelativePath)
            || Heuristics.IsInLineComment(context, match.Index),
    };
}
