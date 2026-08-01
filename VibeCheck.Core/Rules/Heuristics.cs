using System.Text.RegularExpressions;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Shared tests used by rules to discard matches that are not real problems.
/// </summary>
/// <remarks>
/// False positives are what get a security tool uninstalled. A developer who is told three
/// times that <c>apiKey = process.env.API_KEY</c> is a hardcoded credential stops reading
/// the report, and then the true positive in it goes unread too. These helpers exist so
/// precision is a property of the engine rather than something each rule reinvents.
/// </remarks>
public static class Heuristics
{
    private static readonly Regex EnvironmentReference = PatternRule.Compile(
        """
        process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv\(|
        Environment\.GetEnvironmentVariable|ConfigurationManager|IConfiguration|
        \$\{[^}]*\}|%[A-Z_]+%|System\.getenv|ENV\[|dotenv|secrets\.
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    private static readonly Regex PlaceholderText = PatternRule.Compile(
        """
        ^(your|my|the)?[-_ ]?(api|secret|access|private|auth|app)?[-_ ]?(key|token|secret|password|pass|pwd)?
        [-_ ]?(here|goes[-_ ]?here|value|placeholder)?$
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    private static readonly string[] PlaceholderWords =
    [
        "your", "yours", "example", "sample", "placeholder", "changeme", "change_me",
        "dummy", "test", "testing", "fake", "insert", "replace", "todo", "xxx",
        "abc123", "foobar", "lorem", "redacted", "removed", "notreal", "mykey",
    ];

    /// <summary>
    /// True when the value is read from configuration rather than written into the source.
    /// </summary>
    public static bool IsEnvironmentReference(string text) =>
        !string.IsNullOrEmpty(text) && EnvironmentReference.IsMatch(text);

    /// <summary>True when the value is evidently a stand-in rather than a live credential.</summary>
    public static bool IsPlaceholder(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var normalised = value.Trim().Trim('<', '>', '{', '}', '"', '\'');

        if (normalised.Length < 8 || PlaceholderText.IsMatch(normalised))
        {
            return true;
        }

        var lower = normalised.ToLowerInvariant();

        if (PlaceholderWords.Any(word => lower.Contains(word, StringComparison.Ordinal)))
        {
            return true;
        }

        // A single repeated character, as in "xxxxxxxxxxxx" or "000000000000".
        return normalised.Distinct().Count() <= 2;
    }

    /// <summary>
    /// Shannon entropy of the value, in bits per character.
    /// </summary>
    /// <remarks>
    /// This is the workhorse for the generic secret rule. A real credential is drawn from a
    /// large random alphabet and scores around 4 bits or higher; prose, identifiers, and
    /// placeholders draw from a much smaller effective alphabet and score well below that.
    /// It separates <c>"sk_live_4eC39HqLyjWDarjtT1zdp7dc"</c> from <c>"my_api_key_here"</c>
    /// without either appearing on any list.
    /// </remarks>
    public static double ShannonEntropy(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            return 0;
        }

        var frequencies = new Dictionary<char, int>();
        foreach (var c in value)
        {
            frequencies[c] = frequencies.GetValueOrDefault(c) + 1;
        }

        var entropy = 0.0;
        foreach (var count in frequencies.Values)
        {
            var probability = (double)count / value.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    /// <summary>
    /// Whether a value is random-looking enough to be a live credential. The threshold is
    /// tuned to admit real keys while rejecting identifiers and English text.
    /// </summary>
    public static bool LooksLikeRealSecret(string value, double minimumEntropy = 3.2)
    {
        if (IsPlaceholder(value) || IsEnvironmentReference(value))
        {
            return false;
        }

        return value.Length >= 12 && ShannonEntropy(value) >= minimumEntropy;
    }

    private static readonly string[] ConnectionStringMarkers =
    [
        "server=", "data source=", "host=", "initial catalog=", "database=",
        "user id=", "uid=", "port=", "://",
    ];

    /// <summary>
    /// True when the line carries the shape of a database connection string.
    /// </summary>
    /// <remarks>
    /// Anchors the password rule to real connection strings. Without it the rule fired on any
    /// assignment whose identifier merely contained "password", including the Win32 error
    /// constant <c>FILTER_E_PASSWORD = -2147215613</c>.
    /// </remarks>
    public static bool LooksLikeConnectionString(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        return ConnectionStringMarkers.Any(marker =>
            line.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True when the offset sits inside a line comment.
    /// </summary>
    /// <remarks>
    /// Scoped to the matched line rather than tracking block comments or string state across
    /// the file. Commented-out credentials are still leaked credentials, so the aim is only
    /// to drop explanatory prose that happens to contain a keyword.
    /// </remarks>
    public static bool IsInLineComment(RuleContext context, int offset)
    {
        ArgumentNullException.ThrowIfNull(context);

        var line = context.LineText(context.LineAt(offset));
        var trimmed = line.TrimStart();

        return trimmed.StartsWith("//", StringComparison.Ordinal)
            || trimmed.StartsWith('#')
            || trimmed.StartsWith("*", StringComparison.Ordinal)
            || trimmed.StartsWith("<!--", StringComparison.Ordinal);
    }

    /// <summary>
    /// True when <paramref name="guard"/> appears within the preceding lines.
    /// </summary>
    /// <remarks>
    /// Some checks are guarded by an earlier statement rather than on the same line, and a
    /// line-scoped rule cannot see that. A validated shell-open is the standard shape:
    /// <c>if (!Uri.TryCreate(..) || uri.Scheme != Https || uri.Host != "github.com") return;</c>
    /// followed several lines later by the launch. Reporting the launch anyway tells a
    /// developer that code which already does the right thing is still wrong.
    /// </remarks>
    public static bool PrecededBy(RuleContext context, int offset, Regex guard, int lines = 15)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(guard);

        var line = context.LineAt(offset);

        for (var i = Math.Max(1, line - lines); i <= line; i++)
        {
            if (guard.IsMatch(context.LineText(i)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True for files whose contents are examples rather than shipped code.
    /// </summary>
    /// <remarks>
    /// Used to soften rather than suppress: a credential in a fixture is a weaker finding
    /// than one in production code, but keys committed to test files are leaked keys and get
    /// scraped from public repositories exactly the same way.
    /// </remarks>
    public static bool IsTestOrExampleFile(string relativePath)
    {
        ArgumentNullException.ThrowIfNull(relativePath);

        var lower = relativePath.ToLowerInvariant();

        return lower.Contains("/test", StringComparison.Ordinal)
            || lower.Contains("/spec", StringComparison.Ordinal)
            || lower.Contains("/__mocks__", StringComparison.Ordinal)
            || lower.Contains("/example", StringComparison.Ordinal)
            || lower.Contains("/fixture", StringComparison.Ordinal)
            || lower.EndsWith(".test.js", StringComparison.Ordinal)
            || lower.EndsWith(".spec.ts", StringComparison.Ordinal)
            || lower.EndsWith(".example", StringComparison.Ordinal)
            || lower.EndsWith(".sample", StringComparison.Ordinal);
    }

    /// <summary>
    /// True when a match sits in generated or vendored output.
    /// </summary>
    /// <remarks>
    /// Applied only by code-quality rules. Secret rules deliberately ignore this: a key
    /// baked into a minified bundle is shipped to every user and is the most important place
    /// to find one.
    /// </remarks>
    public static bool IsGeneratedCode(string relativePath)
    {
        ArgumentNullException.ThrowIfNull(relativePath);

        var lower = relativePath.ToLowerInvariant();

        return lower.EndsWith(".min.js", StringComparison.Ordinal)
            || lower.EndsWith(".bundle.js", StringComparison.Ordinal)
            || lower.EndsWith(".g.cs", StringComparison.Ordinal)
            || lower.EndsWith(".designer.cs", StringComparison.Ordinal)
            || lower.Contains("/vendor/", StringComparison.Ordinal);
    }
}
