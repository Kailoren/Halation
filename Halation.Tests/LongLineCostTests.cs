using System.Diagnostics;
using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Rules;

namespace Halation.Tests;

/// <summary>
/// What the rules cost on a file that is one enormous line, which is what a minified bundle is.
/// </summary>
/// <remarks>
/// Findings stop at twenty per rule per file, but matches a rule ignores were never capped, and
/// each one searched its whole line again. On a single line the work grew with the square of the
/// file: 20,000 ignored http URLs in a 560 KB package.json took nearly five minutes, so a bundle
/// written to stall the scanner needed nothing cleverer than repetition.
/// </remarks>
public class LongLineCostTests
{
    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    /// <summary>
    /// Each case is a match its rule ignores, repeated along one line, with whatever makes it
    /// ignorable placed at the far end where a search of the whole line finds it last. The counts
    /// are sized so the old cost was between one and twenty seconds per case.
    /// </summary>
    [Theory]
    [InlineData("VC-CODE-001", "a.js", "m=\"Unable to select single public constructor from type {0}\";", "", 20_000)]
    [InlineData("VC-CODE-003", "a.js", "exec(\"a\" + b);", "", 20_000)]
    [InlineData("VC-CODE-004", "a.js", "BinaryFormatter;", "\"x\": false", 20_000)]
    [InlineData("VC-CODE-006", "a.js", "s=\"le des x\";", "", 20_000)]
    [InlineData("VC-SEC-009", "a.js", "password=Tr0ub4dor3x;", "", 5_000)]
    [InlineData("VC-SEC-010", "a.js", "apiKey = \"7Xq2mVn8Kp4Rt6Yw9Zb3\";", "process.env.X", 5_000)]
    [InlineData("VC-CFG-007", "package.json", "\"x\": \"http://example.com/a\",", "\"url\":", 2_000)]
    [InlineData("VC-MAL-007", "a.js", "spawn(x);", "", 30_000)]
    [InlineData("VC-INPUT-004", "A.cs", "await c.GetStringAsync(u);", "maxBytes", 10_000)]
    [InlineData("VC-INPUT-001", "A.cs", "stackalloc char[n];", "n <= 256", 5_000)]
    [InlineData("VC-INPUT-002", "A.cs", "Process.Start(url);", "uri.Scheme != Uri.UriSchemeHttps", 8_000)]
    public void IgnoredMatchesOnOneLine_CostLinearTime(
        string ruleId, string path, string unit, string tail, int count)
    {
        var engine = new RuleEngine();

        // The catalogue compiles its patterns on first use, which is not what is being measured.
        engine.Analyse([File("warm.js", "x")]);

        var content = string.Concat(Enumerable.Repeat(unit, count)) + tail;
        var timer = Stopwatch.StartNew();
        var result = engine.Analyse([File(path, content)]);
        timer.Stop();

        // Proves the case reached the ignore path rather than stopping at the findings cap.
        Assert.DoesNotContain(result.Findings, f => f.RuleId == ruleId);
        Assert.True(
            timer.ElapsedMilliseconds < 1_000,
            $"{ruleId}: {count:N0} ignored matches on one line took {timer.ElapsedMilliseconds:N0} ms");
    }

    /// <summary>
    /// The string-literal test resumes from where the last question about the same line stopped.
    /// Asked in any order, it has to agree with a scan from the start of the line.
    /// </summary>
    [Theory]
    [InlineData("""a = "one \" two" + 'it\'s' + "x\\" + y; z = "\\\"" ;""")]
    [InlineData("""s = 'mixed "quotes" here' + "and 'these'" + done""")]
    [InlineData("""x\"y "a\" b" \' c 'd\\' e "unterminated""")]
    public void StringLiteralScan_AgreesWithAFreshScanInAnyOrder(string line)
    {
        var content = "first line\n" + line + "\r\nlast line";
        var start = content.IndexOf(line, StringComparison.Ordinal);
        var offsets = Enumerable.Range(start - 2, line.Length + 4).ToList();

        var expected = offsets.ToDictionary(
            offset => offset,
            offset => Heuristics.IsInsideStringLiteral(new RuleContext(File("a.js", content)), offset));

        // Forwards as a rule asks, each offset twice as a rule and its Ignore both ask, then
        // backwards as the next rule starts over.
        List<int> order = [.. offsets, .. offsets.SelectMany(o => new[] { o, o }), .. offsets.AsEnumerable().Reverse()];
        var shared = new RuleContext(File("a.js", content));

        Assert.All(order, offset =>
            Assert.True(
                expected[offset] == Heuristics.IsInsideStringLiteral(shared, offset),
                $"disagreed at offset {offset}"));
    }

    private static PatternRule Rule(Regex pattern, Func<Match, RuleContext, bool>? ignore = null) => new()
    {
        Id = "VC-TEST-001",
        Title = "test",
        Severity = Severity.Low,
        UserSeverity = Severity.Low,
        Category = FindingCategory.CodeSafety,
        Description = "test",
        UserDescription = "test",
        Remediation = "test",
        Pattern = pattern,
        Ignore = ignore,
    };

    /// <summary>
    /// A rule's pattern runs as its matches are read, not when they are asked for, so a timeout
    /// arrives inside the loop. It used to escape as a raw regex exception and fail the whole scan
    /// instead of being recorded as one check that did not finish.
    /// </summary>
    [Fact]
    public void PatternTimeout_IsRecordedAsACheckThatDidNotFinish()
    {
        var rule = Rule(new Regex("(x+x+)+y", RegexOptions.None, TimeSpan.FromMilliseconds(50)));

        var result = new RuleEngine([rule]).Analyse([File("a.js", new string('x', 40) + "!y")]);

        Assert.Contains(result.Limitations, l => l.Contains("VC-TEST-001 did not complete", StringComparison.Ordinal));
    }

    /// <summary>The same for a pattern a rule runs while deciding whether to ignore a match.</summary>
    [Fact]
    public void TimeoutInsideAnIgnore_IsRecordedAsACheckThatDidNotFinish()
    {
        var rule = Rule(
            PatternRule.Compile("needle"),
            (_, _) => throw new RegexMatchTimeoutException("needle", "pattern", TimeSpan.FromMilliseconds(1)));

        var result = new RuleEngine([rule]).Analyse([File("a.js", "needle")]);

        Assert.Contains(result.Limitations, l => l.Contains("VC-TEST-001 did not complete", StringComparison.Ordinal));
    }
}
