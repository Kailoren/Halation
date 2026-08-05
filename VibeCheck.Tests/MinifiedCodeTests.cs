using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Reporting;
using VibeCheck.Core.Rules;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Tests;

/// <summary>
/// Code that ships as a bundle rather than as something a person could read.
/// </summary>
/// <remarks>
/// A real application was read in full, reported "100% readable, no known issues found", and was
/// 99% minified. Two separate defects sat behind that sentence: the analysis quietly collapsed,
/// because findings are reported once per line and the file was one line; and nothing in the
/// report said the code was unreadable, so the coverage meter was left implying the opposite.
/// </remarks>
public class MinifiedCodeTests
{
    // ---- Detecting it at all ------------------------------------------------

    /// <summary>
    /// By shape, not by name. The earlier test looked for a <c>.min.js</c> ending and missed an
    /// entire application whose bundles ship as <c>main.js</c> and hashed chunk names.
    /// </summary>
    [Fact]
    public void Minification_is_detected_from_line_length_not_the_file_name()
    {
        Assert.True(File("main.js", new string('x', 5_000)).IsMinified);
        Assert.True(File("_app/chunks/2B_0A94H.js", new string('y', 5_000)).IsMinified);

        var readable = string.Join('\n', Enumerable.Repeat("const value = compute();", 200));

        Assert.False(File("main.js", readable).IsMinified);

        // And the name alone never decides it, in either direction.
        Assert.False(File("vendor.min.js", readable).IsMinified);
    }

    // ---- The analysis must not collapse -------------------------------------

    /// <summary>
    /// The defect worth a test of its own. Findings are reported once per line, which reads the
    /// same problem twice as one problem. In a bundle the file is one line, so twenty unrelated
    /// occurrences read as one.
    /// </summary>
    /// <remarks>
    /// Measured on a real bundle before the fix: removing only the line breaks took VC-MAL-002
    /// from six findings to one and VC-MAL-007 from twenty to one, with raw match counts
    /// unchanged. The score moved from 13 to 29 on byte-identical code.
    /// </remarks>
    [Fact]
    public void The_same_code_is_found_as_often_minified_as_readable()
    {
        var readable = Scan(Occurrences(6, separator: "\n"), "src/app.js");
        var minified = Scan(Occurrences(6, separator: " "), "src/bundle.js");

        Assert.Equal(6, readable.Count(f => f.RuleId == "VC-MAL-002"));
        Assert.Equal(6, minified.Count(f => f.RuleId == "VC-MAL-002"));
    }

    /// <summary>
    /// And the reason the old behaviour was right for readable code still holds: two matches in
    /// the same place are one problem, not two.
    /// </summary>
    [Fact]
    public void Two_matches_in_one_place_are_still_a_single_finding()
    {
        var findings = Scan(
            """const a = open("cookies.sqlite"), b = open("cookies.sqlite");""",
            "src/app.js");

        Assert.Single(findings, f => f.RuleId == "VC-MAL-002");
    }

    // ---- And the reader has to be told --------------------------------------

    [Fact]
    public void The_minified_share_is_measured_by_bytes_not_by_file_count()
    {
        // One large bundle beside several small readable files is not a readable application,
        // and counting files rather than bytes would have called it one.
        var report = Scanned(
            File("bundle.js", new string('x', 40_000)),
            File("a.js", "const a = 1;"),
            File("b.js", "const b = 2;"),
            File("c.js", "const c = 3;"));

        Assert.True(report.Coverage.MinifiedPercent > 99, $"got {report.Coverage.MinifiedPercent}");
        Assert.NotNull(report.MinificationCaveat);
    }

    [Fact]
    public void A_readable_application_is_not_warned_about()
    {
        var report = Scanned(File("a.js", string.Join('\n', Enumerable.Repeat("const a = 1;", 500))));

        Assert.Equal(0, report.Coverage.MinifiedPercent);
        Assert.Null(report.MinificationCaveat);
    }

    /// <summary>
    /// Beside the number. The lesson the dependency caveat already taught: the fact was in the
    /// report all along, several cards below the point where the reader had decided.
    /// </summary>
    [Fact]
    public void The_caveat_reaches_the_export_beside_the_score()
    {
        var report = Scanned(File("bundle.js", new string('x', 40_000)));
        var markdown = MarkdownReportWriter.Write(report);

        Assert.Contains("minified", markdown, StringComparison.OrdinalIgnoreCase);

        var score = markdown.IndexOf(report.Verdict.ScoreDisplay, StringComparison.Ordinal);
        var caveat = markdown.IndexOf("Most of this is minified", StringComparison.Ordinal);

        Assert.True(caveat > score, "the caveat is above the score rather than beside it");
        Assert.True(caveat - score < 900, $"the caveat sits {caveat - score} characters below it");
    }

    // ---- Helpers ------------------------------------------------------------

    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    private static IReadOnlyList<Finding> Scan(string content, string path) =>
        new RuleEngine().Analyse([File(path, content)]).Findings;

    /// <summary>
    /// <paramref name="count"/> separate cookie-database references, each padded well past the
    /// width that counts as one place, so joining them changes the layout and nothing else.
    /// </summary>
    private static string Occurrences(int count, string separator) =>
        string.Join(separator, Enumerable.Range(0, count).Select(i =>
            $$"""const db{{i}} = open("cookies.sqlite"); const pad{{i}} = "{{new string('p', 250)}}";"""));

    /// <summary>A report over the given files, with everything not under test left inert.</summary>
    private static ScanReport Scanned(params RecoveredFile[] files)
    {
        var findings = new RuleEngine().Analyse(files).Findings;

        long total = files.Sum(f => (long)f.Content.Length);
        long minified = files.Where(f => f.IsMinified).Sum(f => (long)f.Content.Length);

        return new ScanReport
        {
            ArtifactName = "fixture",
            Kind = ArtifactKind.SourceTree,
            ArtifactBytes = total,
            Sha256 = new string('0', 64),
            ScannedAt = DateTimeOffset.UnixEpoch,
            Verdict = ScoreCalculator.Calculate(findings),
            Coverage = new CoverageReport
            {
                Percent = 100,
                Basis = "fixture",
                RecoveredFileCount = files.Length,
                RecoveredBytes = total,
                MinifiedPercent = total == 0 ? 0 : (int)Math.Round(minified / (double)total * 100),
            },
            Findings = findings,
            CategoryScores = ScoreCalculator.CategoryScores(findings),
            VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
            Effort = new ScanEffort
            {
                RecoveryMethod = "fixture",
                FilesRecovered = files.Length,
                BytesRecovered = total,
                ChecksRun = 40,
                FilesChecked = files.Length,
                PackagesResolved = 0,
                PackagesChecked = 0,
                VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
            },
            ScannerVersion = "test",
        };
    }
}
