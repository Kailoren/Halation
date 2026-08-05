using System.Text;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;

namespace VibeCheck.Tests;

/// <summary>
/// A scanner is a program whose source contains, in quotation marks, every string it looks for.
/// </summary>
/// <remarks>
/// Pointed at its own published build, VibeCheck scored 16/100 on nine findings, none of them
/// real, and advised against installing itself for reading cryptocurrency wallets. Every other
/// detection tool has the same shape. These tests hold both ends of the fix: that a rule table
/// is not mistaken for the behaviour it describes, and that ordinary code is untouched by it.
/// </remarks>
public class PatternDefinitionTests
{
    private static readonly RuleEngine Engine = new();

    private static RuleEngineResult Scan(string content, string path = "src/Rules.cs") =>
        Engine.Analyse(
        [
            new RecoveredFile
            {
                RelativePath = path,
                Content = content,
                Language = RecoveredFile.LanguageOf(path),
            },
        ]);

    /// <summary>Roughly the shape of this project's own rule files, in miniature.</summary>
    private const string RuleTable = """
        private static PatternRule Deserialisation { get; } = new()
        {
            Id = "VC-CODE-004",
            Pattern = PatternRule.Compile("(?:BinaryFormatter|NetDataContractSerializer)"),
        };
        private static PatternRule Cipher { get; } = new()
        {
            Id = "VC-CODE-006",
            Description = "The application uses DES, RC4, or ECB mode.",
            Pattern = PatternRule.Compile("(?:\\bDES\\b|\\bRC4\\b|CipherMode\\.ECB)"),
        };
        private static PatternRule Tls { get; } = new()
        {
            Pattern = PatternRule.Compile("(?:SslProtocols\\.(?:Ssl3|Tls)|ServerCertificateValidationCallback)"),
        };
        private static PatternRule Startup { get; } = new()
        {
            Pattern = PatternRule.Compile("(?:CurrentVersion[\\\\/]+Run|schtasks)"),
        };
        """;

    [Fact]
    public void A_rule_table_is_not_taken_for_the_behaviour_it_describes()
    {
        var result = Scan(RuleTable);

        Assert.Empty(result.Findings);
        Assert.True(result.MatchesDiscounted > 0);
    }

    /// <summary>
    /// The other half, and the one that matters more. Real code doing the real thing is
    /// unaffected, because it is not in quotation marks.
    /// </summary>
    [Fact]
    public void Ordinary_code_doing_the_same_thing_is_still_reported()
    {
        var result = Scan("""
            var formatter = new BinaryFormatter();
            var data = formatter.Deserialize(stream);
            handler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
            """);

        Assert.Contains(result.Findings, f => f.RuleId == "VC-CODE-004");
        Assert.Equal(0, result.MatchesDiscounted);
    }

    /// <summary>
    /// One pattern in an otherwise ordinary file still counts, provided the string it sits in
    /// is the one being compiled.
    /// </summary>
    [Fact]
    public void A_single_regex_in_ordinary_code_is_enough()
    {
        var result = Scan("""
            private static readonly Regex Surface = new Regex("BinaryFormatter|LosFormatter");
            """);

        Assert.Empty(result.Findings);

        // Two, because both alternatives inside the pattern are things VC-CODE-004 looks for,
        // and each is discounted on its own.
        Assert.Equal(2, result.MatchesDiscounted);
    }

    /// <summary>
    /// A minified bundle is one line, so "inside a string on this line" and "what precedes it
    /// on this line" stop meaning anything and the guard swallows the file.
    /// </summary>
    /// <remarks>
    /// Found on a real Electron application: four <c>require("child_process")</c> imports were
    /// discounted as pattern definitions, because a megabyte-long line contained a regex
    /// somewhere and every string in it therefore looked like an argument to one. The first cut
    /// of this guard had no bound on either test, which is precisely how a precision fix turns
    /// into a hole.
    /// </remarks>
    [Fact]
    public void A_minified_bundle_is_not_mistaken_for_a_rule_table()
    {
        var bundle =
            "var a=new RegExp(\"^x$\"),b=new RegExp(\"^y$\"),c=new RegExp(\"^z$\"),d=new RegExp(\"^w$\"),"
            + new string('_', 3000)
            + ",e=O(\"child_process\"),f=require(\"BinaryFormatter\");";

        var result = Scan(bundle, "dist/main.js");

        Assert.Equal(0, result.MatchesDiscounted);
    }

    /// <summary>
    /// The case a real application exposed, and the reason the test is density rather than a
    /// count.
    /// </summary>
    /// <remarks>
    /// A bundled Electron cleaner carried eighteen regular expressions across twenty-nine
    /// thousand lines. That cleared an absolute threshold of four, every string literal in the
    /// file was exempted as a consequence, and six references to a browser cookie database were
    /// found and discounted in silence. The application scored 100/100 with no findings. Any
    /// bundle is long enough to clear a fixed count, so the exemption reached nearly all of them.
    /// </remarks>
    [Fact]
    public void A_long_file_with_a_scattering_of_patterns_is_not_a_catalogue()
    {
        var result = Scan(BundleShaped(lines: 2_000, patterns: 5), "out/main/index.js");

        Assert.Contains(result.Findings, f => f.RuleId == "VC-MAL-002");
    }

    /// <summary>
    /// The same five definitions packed into a file the size of a rule table still are one.
    /// Paired with the test above deliberately: the two differ only in how much ordinary code
    /// surrounds the patterns, which is exactly the thing a count cannot see.
    /// </summary>
    [Fact]
    public void The_same_patterns_packed_into_a_rule_table_still_count_as_one()
    {
        var result = Scan(BundleShaped(lines: 40, patterns: 5), "src/Rules.cs");

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VC-MAL-002");
        Assert.True(result.MatchesDiscounted > 0);
    }

    /// <summary>
    /// Ordinary lines carrying <paramref name="patterns"/> regex definitions and one reference
    /// to a browser cookie database, quoted the way a real one is.
    /// </summary>
    private static string BundleShaped(int lines, int patterns)
    {
        var builder = new StringBuilder();

        builder.AppendLine("""const dbFiles = { firefox: ["places.sqlite", "cookies.sqlite"] };""");

        var every = lines / patterns;

        for (var i = 0; i < lines; i++)
        {
            builder.AppendLine(i % every == 0
                ? $$"""const match{{i}} = new RegExp("^opt{{i}}$");"""
                : $"const value{i} = compute({i});");
        }

        return builder.ToString();
    }

    /// <summary>
    /// A credential in quotation marks is a leaked credential wherever it lives, including in
    /// the source of a security tool.
    /// </summary>
    [Fact]
    public void Secrets_are_never_discounted()
    {
        var result = Scan(RuleTable + """

            private const string Key = "sk_live_4eC39HqLyjWDarjtT1zdp7dcabcd";
            """);

        Assert.Contains(result.Findings, f => f.Category == FindingCategory.Secrets);
    }

    /// <summary>
    /// Not dropped in silence. A tool that quietly removes its own findings is asking to be
    /// trusted about the one thing nobody can check.
    /// </summary>
    [Fact]
    public void The_scan_says_how_many_it_discounted()
    {
        var effort = new ScanEffort
        {
            RecoveryMethod = "test",
            FilesRecovered = 1,
            BytesRecovered = 1,
            ChecksRun = 40,
            FilesChecked = 1,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = VibeCheck.Core.Dependencies.VulnerabilityDataProvenance.Unavailable,
            MatchesDiscounted = 28,
        };

        var line = Assert.Single(
            effort.Describe(DateTimeOffset.UnixEpoch),
            l => l.Contains("Discounted", StringComparison.Ordinal));

        Assert.Contains("28", line, StringComparison.Ordinal);
    }

    /// <summary>A scan that discounted nothing says nothing about it.</summary>
    [Fact]
    public void A_scan_that_discounted_nothing_stays_quiet_about_it()
    {
        var effort = new ScanEffort
        {
            RecoveryMethod = "test",
            FilesRecovered = 1,
            BytesRecovered = 1,
            ChecksRun = 40,
            FilesChecked = 1,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = VibeCheck.Core.Dependencies.VulnerabilityDataProvenance.Unavailable,
        };

        Assert.DoesNotContain(
            effort.Describe(DateTimeOffset.UnixEpoch),
            l => l.Contains("Discounted", StringComparison.Ordinal));
    }

    // ---- The string-literal test itself -------------------------------------

    private static bool Inside(string line, string needle)
    {
        var context = new RuleContext(new RecoveredFile
        {
            RelativePath = "src/app.cs",
            Content = line,
            Language = SourceLanguage.CSharp,
        });

        return Heuristics.IsInsideStringLiteral(context, line.IndexOf(needle, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("""var x = "hello world";""", "world", true)]
    [InlineData("""var world = 1;""", "world", false)]

    // The case the whole thing runs on: a pattern full of escaped backslashes must not read as
    // a string that ended early.
    [InlineData("""Compile("(?:a[\\\\/]world|b)");""", "world", true)]

    // An escaped quote does not close the string either.
    [InlineData("""var x = "he said \"world\" loudly";""", "loudly", true)]
    [InlineData("""var a = "one"; var world = 2;""", "world", false)]
    public void Reads_string_boundaries_the_way_the_language_does(
        string line, string needle, bool inside) =>
        Assert.Equal(inside, Inside(line, needle));
}
