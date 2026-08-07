using System.Text.RegularExpressions;

namespace Halation.Core.Rules;

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
    /// Calls that turn a string into a search pattern, in the languages this scanner reads.
    /// </summary>
    private static readonly Regex PatternConstruction = PatternRule.Compile(
        """
        new\s+Regex|new\s+RegExp|Regex\.(?:IsMatch|Match|Matches|Replace|Split)|
        \bre\.compile|\.Compile\s*\(
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// The fewest pattern definitions that can make a file a catalogue of them, whatever its
    /// size.
    /// </summary>
    /// <remarks>
    /// A floor, not the test. Four definitions is a rule table in a file of forty lines and
    /// nothing whatever in a file of thirty thousand, which is why
    /// <see cref="MinimumCataloguePer1000Lines"/> carries the judgment.
    /// </remarks>
    private const int PatternCatalogueThreshold = 4;

    /// <summary>
    /// How densely those definitions must sit before a file is a catalogue of patterns rather
    /// than code that happens to use a few.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The count above was once the entire test, and a real application showed what that costs.
    /// A bundled Electron cleaner carried eighteen regular expressions spread across
    /// twenty-nine thousand lines, cleared a threshold of four on the strength of them, and had
    /// every string literal in the file exempted as a result. Six references to a browser
    /// cookie database were found and silently discounted, and the application scored 100/100
    /// with no findings at all. Any bundled application is large enough to clear an absolute
    /// count, so the exemption applied to very nearly all of them.
    /// </para>
    /// <para>
    /// Read off a distribution of real files rather than chosen. In this project's own
    /// decompiled build the five genuine rule tables sit between 40 and 61 per thousand lines;
    /// across three real applications no other file reaches four definitions at all; the two
    /// bundles that caused the problem sit at 0.62 and 0.07. Twenty is half the lowest real
    /// catalogue and thirty times the densest bundle, so neither margin is tight.
    /// </para>
    /// </remarks>
    private const double MinimumCataloguePer1000Lines = 20;

    /// <summary>
    /// Average line length past which a file is a bundle rather than something written by hand.
    /// </summary>
    /// <remarks>
    /// The line is the unit every test below works in, and a minified bundle does not have
    /// them: a megabyte of JavaScript arrives as one line, so "is this inside a string" and
    /// "what precedes it on this line" stop meaning anything. Measured on a real Electron
    /// application, that made four <c>require("child_process")</c> imports look like pattern
    /// definitions. Bundles are excluded rather than guessed at.
    /// </remarks>
    private const int MaxAverageLineLength = 200;

    /// <summary>How far back to look for the call that turns this string into a pattern.</summary>
    /// <remarks>
    /// Bounded, for the same reason. Without a bound the search runs to the start of the line,
    /// which in bundled code is the start of the file, and finds a regex somewhere in the
    /// bundle every time.
    /// </remarks>
    private const int PatternConstructionLookback = 400;

    /// <summary>Whether a file holds enough pattern definitions to be a catalogue of them.</summary>
    public static bool CountsAsPatternCatalogue(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (content.Length == 0)
        {
            return false;
        }

        var lines = CountLines(content);

        // A bundle arrives as one enormous line, where definitions per line means nothing and
        // any file containing a handful would read as infinitely dense. Excluded before the
        // ratio is taken rather than by it.
        if (content.Length / lines > MaxAverageLineLength)
        {
            return false;
        }

        // Scaled to the file, so the bar a rule table clears in forty lines is not one a
        // bundled application clears merely by being long.
        var required = Math.Max(
            PatternCatalogueThreshold,
            (int)Math.Ceiling(lines * MinimumCataloguePer1000Lines / 1000.0));

        var found = 0;

        foreach (Match _ in PatternConstruction.Matches(content))
        {
            if (++found >= required)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Lines in the content, counting the last whether or not it is terminated.</summary>
    private static int CountLines(string content)
    {
        var lines = 1;

        foreach (var c in content)
        {
            if (c == '\n')
            {
                lines++;
            }
        }

        return lines;
    }

    /// <summary>
    /// True when the offset falls inside a quoted string on its own line.
    /// </summary>
    /// <remarks>
    /// Line-scoped and deliberately simple. Escapes are honoured so that a pattern full of
    /// <c>\\</c> does not read as the string ending early, which is exactly the text this is
    /// used on. Both quote characters count, because the languages here disagree about which
    /// one makes a string.
    /// </remarks>
    public static bool IsInsideStringLiteral(RuleContext context, int offset)
    {
        ArgumentNullException.ThrowIfNull(context);

        var line = context.LineText(context.LineAt(offset));
        var target = context.OffsetInLine(offset);

        if (target <= 0 || target >= line.Length)
        {
            return false;
        }

        var quote = '\0';

        for (var i = 0; i < target; i++)
        {
            var c = line[i];

            if (c == '\\' && quote != '\0')
            {
                // Consumes whatever it escapes, so an escaped quote does not close the string.
                i++;
                continue;
            }

            if (c is not ('"' or '\''))
            {
                continue;
            }

            if (quote == '\0')
            {
                quote = c;
            }
            else if (quote == c)
            {
                quote = '\0';
            }
        }

        return quote != '\0';
    }

    /// <summary>
    /// True when a match is a pattern being defined rather than code being run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A security scanner is a program whose source contains, in quotation marks, every string
    /// it looks for. Pointed at itself or at any other detection tool it reports its own rule
    /// table as the thing the rules detect: Halation's published build scored 16/100 on nine
    /// findings, none of them real, including a "do not install" for reading cryptocurrency
    /// wallets. Antivirus signatures, WAF rules and linter configurations all have this shape.
    /// </para>
    /// <para>
    /// Two conditions, both required. The match sits inside a string literal, so it cannot be
    /// a call to the thing it names, and either that string is being handed to a regex
    /// constructor or the file around it holds enough pattern definitions to be a catalogue of
    /// them. Ordinary code satisfies neither: a real <c>new BinaryFormatter()</c> is not in
    /// quotes, and a real registry path in quotes does not sit in a file of forty regexes.
    /// </para>
    /// <para>
    /// What this gives up, stated plainly: an application that hides its behaviour by keeping
    /// it in regular expressions inside a file dressed as a rule table would be discounted
    /// here. That is a deliberate act of evasion rather than the accident this guards against,
    /// and the report says how many matches it discounted rather than dropping them in silence.
    /// Secrets are exempt, because a key in quotes is a leaked key wherever it lives.
    /// </para>
    /// </remarks>
    public static bool IsPatternDefinition(RuleContext context, int offset)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!IsInsideStringLiteral(context, offset))
        {
            return false;
        }

        if (context.IsPatternCatalogue)
        {
            return true;
        }

        // A single pattern in an otherwise ordinary file still counts, provided the string the
        // match sits in is the argument being compiled. Searched within a bounded window rather
        // than back to the start of the line, so that bundled code, where the line is the whole
        // file, cannot satisfy this by containing a regex anywhere at all.
        var line = context.LineText(context.LineAt(offset));
        var end = Math.Min(context.OffsetInLine(offset), line.Length);
        var start = Math.Max(0, end - PatternConstructionLookback);

        return PatternConstruction.IsMatch(line[start..end]);
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
