using System.Text;
using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.Rules;

/// <summary>
/// Detects credentials committed into source or baked into shipped bundles.
/// </summary>
/// <remarks>
/// The most common failure in AI-generated projects: the assistant writes the key inline
/// because that is what makes the example run, and it travels into the repository and the
/// build. None of these rules block, deliberately. A leaked credential harms the developer
/// whose key it is, and "do not install" is reserved for what endangers the installing user.
/// </remarks>
public static class SecretRules
{
    /// <summary>
    /// Computed on access rather than stored in an initialiser: static initialisers run in
    /// declaration order, so a stored list declared above the rules would capture nulls.
    /// </summary>
    public static IReadOnlyList<IRule> All =>
    [
        PrivateKey,
        AwsAccessKey,
        StripeLiveKey,
        GoogleApiKey,
        GitHubToken,
        SlackToken,
        AnthropicApiKey,
        OpenAiApiKey,
        ConnectionStringPassword,
        GenericHighEntropySecret,
        new SupabaseServiceKeyRule(),
    ];

    private static PatternRule PrivateKey { get; } = new()
    {
        Id = "VC-SEC-001",
        Title = "Private key committed to the application",
        Severity = Severity.Critical,
        UserSeverity = Severity.Low,
        Category = FindingCategory.Secrets,
        Description =
            "A PEM-encoded private key is embedded in the application. Anyone with a copy of "
            + "the application has the key, and can impersonate whatever it authenticates.",
        Remediation =
            "Revoke and reissue the key immediately, then load the replacement from a secret "
            + "store or environment variable at runtime. Rewrite git history if it was committed, "
            + "since deleting the file in a later commit leaves it fully retrievable.",
        UserDescription =
            "This application carries a private key that anyone with a copy of it also has. The "
            + "key belongs to whoever built the app, so the direct loss is theirs, but if it is the "
            + "key that proves the identity of a service this app talks to, someone else could "
            + "stand in for that service and feed the app whatever they liked.",
        UserRemediation =
            "Nothing you can fix. Treat anything this app tells you it fetched from its own "
            + "servers with a little more caution than usual.",
        Pattern = PatternRule.Compile(
            """-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"""),
    };

    private static PatternRule AwsAccessKey { get; } = new()
    {
        Id = "VC-SEC-002",
        Title = "AWS access key identifier in source",
        Severity = Severity.Critical,
        UserSeverity = Severity.Low,
        Category = FindingCategory.Secrets,
        Description =
            "An AWS access key identifier appears in the application. Paired with its secret, "
            + "it grants direct access to the account's resources, and automated scrapers find "
            + "these within minutes of publication.",
        Remediation =
            "Deactivate the key in IAM now, then issue a replacement. Prefer IAM roles or short-lived "
            + "credentials over long-lived keys, and confirm the key was not also committed to history.",
        UserDescription =
            "The developer left their cloud account key inside the application. Anyone who "
            + "downloaded this app has it too. This is mostly their bill and their infrastructure, "
            + "but if the app stores your files or your data in that account, everyone else with "
            + "the app can reach it as well.",
        UserRemediation ="If you have uploaded anything private through this app, assume it is not private.",
        Pattern = PatternRule.Compile("""\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b"""),
        SecretGroup = "1",
    };

    private static PatternRule StripeLiveKey { get; } = new()
    {
        Id = "VC-SEC-003",
        Title = "Live Stripe secret key in source",
        Severity = Severity.Critical,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "A live-mode Stripe secret key is embedded in the application. It can create charges, "
            + "issue refunds, and read customer records against the real account.",
        Remediation =
            "Roll the key in the Stripe dashboard immediately and review recent API activity. "
            + "Secret keys belong on the server only, never in client or desktop code.",
        UserDescription =
            "The developer left their payment provider key inside the application, which means "
            + "anyone with the app can act on their payment account. This is a real problem for "
            + "them and costs you nothing: your own card details are not in this key and are not "
            + "exposed by it.",
        Pattern = PatternRule.Compile("""\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})"""),
        SecretGroup = "1",
    };

    private static PatternRule GoogleApiKey { get; } = new()
    {
        Id = "VC-SEC-004",
        Title = "Google API key in source",
        Severity = Severity.High,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "A Google API key is embedded in the application. Unless restricted, it can be "
            + "extracted and used against the owner's quota and billing account.",
        Remediation =
            "Restrict the key by referrer, IP, or application in the Google Cloud console, and "
            + "rotate it if it has been published unrestricted.",
        UserDescription =
            "The developer left one of their own service keys inside the application. Someone "
            + "could run up charges on their account. It does not give anyone access to you or your "
            + "machine.",
        Pattern = PatternRule.Compile("""\b(AIza[0-9A-Za-z_\-]{35})\b"""),
        SecretGroup = "1",
    };

    private static PatternRule GitHubToken { get; } = new()
    {
        Id = "VC-SEC-005",
        Title = "GitHub token in source",
        Severity = Severity.Critical,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "A GitHub personal access or app token is embedded in the application. Depending on "
            + "its scopes it can read private repositories or push code.",
        Remediation =
            "Revoke the token in GitHub settings and issue a replacement with the narrowest scopes "
            + "that work. Enable push protection on the repository to block future commits.",
        UserDescription =
            "The developer left a token for their own source code account inside the application. "
            + "It exposes their code, not you.",
        Pattern = PatternRule.Compile("""\b(gh[pousr]_[A-Za-z0-9]{36,})\b"""),
        SecretGroup = "1",
    };

    private static PatternRule SlackToken { get; } = new()
    {
        Id = "VC-SEC-006",
        Title = "Slack token in source",
        Severity = Severity.High,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "A Slack API token is embedded in the application, granting whatever workspace access "
            + "its scopes allow.",
        Remediation = "Revoke the token in the Slack app configuration and load its replacement from configuration.",
        UserDescription =
            "The developer left a token for their own team chat inside the application. Someone "
            + "could read or post in their workspace. It has nothing to do with your machine or "
            + "your data.",
        Pattern = PatternRule.Compile("""\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"""),
        SecretGroup = "1",
    };

    private static PatternRule AnthropicApiKey { get; } = new()
    {
        Id = "VC-SEC-007",
        Title = "Anthropic API key in source",
        Severity = Severity.Critical,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "An Anthropic API key is embedded in the application. Anyone holding it can bill usage "
            + "to the owner's account.",
        Remediation =
            "Revoke the key in the Anthropic console and load its replacement from an environment "
            + "variable. Calls that need a key should be proxied through a server you control rather "
            + "than made from client or desktop code.",
        UserDescription =
            "The developer left their own AI service key inside the application, so anyone with "
            + "the app can spend their money on it. Annoying for them, harmless to you.",
        Pattern = PatternRule.Compile("""\b(sk-ant-[A-Za-z0-9_\-]{20,})"""),
        SecretGroup = "1",
    };

    private static PatternRule OpenAiApiKey { get; } = new()
    {
        Id = "VC-SEC-008",
        Title = "OpenAI API key in source",
        Severity = Severity.Critical,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Secrets,
        Description =
            "An OpenAI API key is embedded in the application. Anyone holding it can bill usage to "
            + "the owner's account.",
        Remediation =
            "Revoke the key in the OpenAI dashboard and load its replacement from configuration. "
            + "Proxy model calls through a server rather than shipping a key to users.",
        UserDescription =
            "The developer left their own AI service key inside the application, so anyone with "
            + "the app can spend their money on it. Annoying for them, harmless to you.",
        Pattern = PatternRule.Compile("""\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"""),
        SecretGroup = "1",
        // The Anthropic rule matches the same shape; let the more specific one win.
        Ignore = (match, _) => match.Value.StartsWith("sk-ant-", StringComparison.Ordinal),
    };

    private static PatternRule ConnectionStringPassword { get; } = new()
    {
        Id = "VC-SEC-009",
        Title = "Database connection string contains a password",
        Severity = Severity.High,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.Secrets,
        Description =
            "A connection string with an inline password is embedded in the application. If the "
            + "database is reachable from the internet, this is direct access to its contents.",
        Remediation =
            "Move the connection string to configuration or a secret store, rotate the password, "
            + "and restrict the database to known networks.",
        UserDescription =
            "The application carries the username and password for a database. Everyone who "
            + "downloaded this app has those same details, so anyone who looks can connect to that "
            + "database directly. If it holds accounts, messages, or anything else you have given "
            + "this app, other people can read and change it.",
        UserRemediation =
            "Assume anything you have stored through this app is readable by strangers. Do not "
            + "put anything sensitive into it, and change any password you have reused elsewhere.",
        Pattern = PatternRule.Compile(
            """(?:password|pwd)\s*=\s*(?<secret>[^;"'\s]{6,})""",
            RegexOptions.IgnoreCase),
        SecretGroup = "secret",
        Ignore = (match, context) =>
        {
            var secret = match.Groups["secret"].Value;
            var line = context.LineFor(match);

            // A numeric assignment is a constant, not a credential. Observed firing on the
            // Win32 error constant FILTER_E_PASSWORD = -2147215613.
            if (secret.All(c => char.IsAsciiDigit(c) || c is '-' or '+' or 'x' or 'X')
                || Heuristics.IsPlaceholder(secret)
                || Heuristics.IsEnvironmentReference(line))
            {
                return true;
            }

            // Anchor to an actual connection string rather than to any assignment whose
            // identifier happens to contain "password".
            return !Heuristics.LooksLikeConnectionString(line);
        },
    };

    /// <summary>
    /// The catch-all for credentials that follow no vendor-specific format.
    /// </summary>
    /// <remarks>
    /// This is the highest-risk rule for false positives, so it is gated on entropy rather
    /// than on the variable name alone. An assignment only reports when its value is long,
    /// random-looking, not a placeholder, and not read from configuration.
    /// </remarks>
    private static PatternRule GenericHighEntropySecret { get; } = new()
    {
        Id = "VC-SEC-010",
        Title = "Hardcoded credential in source",
        Severity = Severity.High,
        UserSeverity = Severity.Low,
        Category = FindingCategory.Secrets,
        Description =
            "A variable whose name indicates a credential is assigned a literal, random-looking "
            + "value. Anything shipped to a user can be read back out of the application, so a "
            + "credential embedded this way should be treated as public.",
        Remediation =
            "Load the value from an environment variable or secret store at runtime, and rotate it "
            + "if the application has already been distributed.",
        UserDescription =
            "A password or key is written directly into the application, so it is the same for "
            + "everyone who downloaded it. What it unlocks is not clear from the code, so it cannot "
            + "be ruled out that something of yours sits behind it.",
        Pattern = PatternRule.Compile(
            """
            (?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|
            client[_-]?secret|private[_-]?key|password|passwd)
            \s*[:=]\s*
            ["'](?<secret>[^"'\s]{12,})["']
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
        SecretGroup = "secret",
        Ignore = (match, context) =>
            !Heuristics.LooksLikeRealSecret(match.Groups["secret"].Value)
            || Heuristics.IsEnvironmentReference(context.LineFor(match))
            || Heuristics.IsInLineComment(context, match.Index),
    };
}

/// <summary>
/// Detects a Supabase <c>service_role</c> key shipped to clients.
/// </summary>
/// <remarks>
/// Supabase issues two keys that look identical: <c>anon</c>, which is meant to be public and
/// is constrained by row-level security, and <c>service_role</c>, which bypasses it entirely.
/// Telling them apart means decoding the payload and reading the role claim, which is what this
/// does. A shipped <c>service_role</c> key is read and write on every row for anyone who opens
/// the bundle.
/// </remarks>
public sealed class SupabaseServiceKeyRule : IRule
{
    private static readonly Regex JsonWebToken = PatternRule.Compile(
        """\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b""");

    public string Id => "VC-SEC-011";

    public string Title => "Supabase service key";

    public FindingCategory Category => FindingCategory.Secrets;

    public bool AppliesTo(RecoveredFile file) => true;

    public IEnumerable<Finding> Examine(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();
        var seenLines = new HashSet<int>();

        foreach (Match match in JsonWebToken.Matches(context.Content))
        {
            var token = match.Groups[1].Value;

            if (DecodePayload(token) is not { } payload)
            {
                continue;
            }

            var isServiceRole = payload.Contains("\"service_role\"", StringComparison.Ordinal)
                                || payload.Contains("'service_role'", StringComparison.Ordinal);

            if (!isServiceRole)
            {
                // The anon key is designed to be published; reporting it would be noise.
                continue;
            }

            var line = context.LineAt(match.Index);
            if (!seenLines.Add(line))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                Title = "Supabase service_role key shipped in the application",
                Severity = Severity.Critical,
                UserSeverity = Severity.High,
                UserDescription =
                    "This application carries a master key to its database, one that overrides every "
                    + "access restriction. Anyone who downloaded the app can pull it out and then read, "
                    + "change, or delete every record in that database, including anything belonging to "
                    + "other people who use it.",
                UserRemediation =
                    "Assume everything you have put into this application is visible to strangers and can "
                    + "be altered by them. Do not store anything private in it, and change any password you "
                    + "have reused elsewhere.",
                Category = FindingCategory.Secrets,
                Description =
                    "This is a Supabase service_role key, not the anon key. The service_role key "
                    + "bypasses row-level security completely, so anyone who extracts it from the "
                    + "application has unrestricted read and write access to every row in the "
                    + "database, regardless of what policies are configured.",
                Remediation =
                    "Treat the database as compromised: rotate the service_role key in the Supabase "
                    + "dashboard immediately and audit recent activity. Use the anon key in client "
                    + "code with row-level security enabled on every table, and keep the service_role "
                    + "key on a server the user cannot reach.",
                FilePath = context.File.RelativePath,
                Line = line,
                Evidence = Redaction.BuildEvidence(context.LineText(line), token),
                Source = FindingSource.Rule,
                Reference = "https://supabase.com/docs/guides/api/api-keys",
            });
        }

        return findings;
    }

    /// <summary>
    /// Decodes the claims segment of a JWT. Signature validity is irrelevant here: the
    /// question is only which role the token asserts.
    /// </summary>
    private static string? DecodePayload(string token)
    {
        var segments = token.Split('.');
        if (segments.Length < 2)
        {
            return null;
        }

        try
        {
            var payload = segments[1].Replace('-', '+').Replace('_', '/');
            var padded = payload.PadRight((payload.Length + 3) / 4 * 4, '=');

            return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        }
        catch (FormatException)
        {
            return null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}
