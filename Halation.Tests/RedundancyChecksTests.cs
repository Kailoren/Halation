using Halation.Core.Model;
using Halation.Core.Quality;
using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Duplication is the one thing decompiled output is guaranteed to fake, so the gate keeping
/// this check away from it is the part most worth testing. Everything else here is about
/// precision: a maintainability check that cries wolf gets the whole report skimmed, and the
/// findings that matter go unread with it.
/// </summary>
public class RedundancyChecksTests
{
    private static RecoveredFile File(string path, string content, bool decompiled = false) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
        IsDecompiled = decompiled,
    };

    /// <summary>Twelve significant lines, the minimum a repeat has to reach.</summary>
    private static string Block(string tag) =>
        string.Join('\n', Enumerable.Range(1, 14).Select(i => $"var {tag}{i} = compute({i});"));

    // ---- The gate ----------------------------------------------------------

    /// <summary>
    /// The whole reason this check is scoped the way it is. Decompilers generate repetition
    /// the author never wrote: state machines for async and iterators, display classes for
    /// closures, one copy per generic instantiation. Reporting that as the author's duplication
    /// would be confidently wrong, which costs more than saying nothing.
    /// </summary>
    [Fact]
    public void Decompiled_files_are_never_compared()
    {
        var result = RedundancyChecks.Run(
        [
            File("A.cs", Block("x"), decompiled: true),
            File("B.cs", Block("x"), decompiled: true),
        ]);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Says_out_loud_that_decompiled_files_were_skipped()
    {
        var result = RedundancyChecks.Run(
        [
            File("A.cs", Block("x"), decompiled: true),
            File("B.cs", Block("x"), decompiled: true),
        ]);

        Assert.Contains(
            result.Limitations,
            l => l.Contains("decompiler", StringComparison.Ordinal));
    }

    /// <summary>
    /// A mixed artifact gets the right treatment per file rather than all or nothing: the
    /// verbatim half is still worth comparing.
    /// </summary>
    [Fact]
    public void Compares_the_verbatim_files_in_a_mixed_artifact()
    {
        var result = RedundancyChecks.Run(
        [
            File("Decompiled.cs", Block("x"), decompiled: true),
            File("a/Real.js", Block("y")),
            File("b/Real.js", Block("y")),
        ]);

        Assert.NotEmpty(result.Findings);
        Assert.All(result.Findings, f => Assert.DoesNotContain("Decompiled", f.Evidence ?? ""));
    }

    // ---- What it finds -----------------------------------------------------

    [Fact]
    public void Finds_two_identical_files()
    {
        var result = RedundancyChecks.Run(
            [File("a/helpers.js", Block("x")), File("b/helpers.js", Block("x"))]);

        Assert.Contains(result.Findings, f => f.RuleId == "VC-DUP-001");
    }

    [Fact]
    public void Finds_a_block_repeated_across_files()
    {
        var result = RedundancyChecks.Run(
        [
            File("one.js", "function a() {\n" + Block("q") + "\n}\nvar unique1 = 1;"),
            File("two.js", "function b() {\n" + Block("q") + "\n}\nvar unique2 = 2;"),
        ]);

        Assert.Contains(result.Findings, f => f.RuleId == "VC-DUP-002");
    }

    [Fact]
    public void Finds_commented_out_code()
    {
        var commented = string.Join('\n',
            Enumerable.Range(1, 8).Select(i => $"// var dead{i} = compute({i});"));

        var result = RedundancyChecks.Run([File("a.js", commented + "\nvar live = 1;")]);

        Assert.Contains(result.Findings, f => f.RuleId == "VC-DUP-003");
    }

    // ---- Precision ---------------------------------------------------------

    /// <summary>
    /// The most valuable thing in a file is a comment explaining why something is done.
    /// Reporting prose as dead weight would be actively harmful advice.
    /// </summary>
    [Fact]
    public void Explanatory_comments_are_not_mistaken_for_dead_code()
    {
        var prose = string.Join('\n',
        [
            "// This exists because the upstream service returns dates in two formats.",
            "// The first is documented and the second is not, so both are handled here.",
            "// Removing either one breaks a customer we cannot reach for testing.",
            "// See the incident write-up for the full history of why this is like this.",
            "// Do not simplify without reading it first.",
            "// Seriously, do not.",
            "// It has been simplified twice and reverted twice.",
        ]);

        var result = RedundancyChecks.Run([File("a.js", prose + "\nvar live = 1;")]);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VC-DUP-003");
    }

    /// <summary>
    /// Every file in a project shares its imports and its closing braces. Matching on those
    /// would report the language's own boilerplate as duplicated work.
    /// </summary>
    [Fact]
    public void Shared_imports_and_braces_are_not_duplication()
    {
        var imports = string.Join('\n', Enumerable.Range(1, 20).Select(i => $"import m{i} from 'm{i}';"));

        var result = RedundancyChecks.Run(
        [
            File("one.js", imports + "\n}\n}\n}\nvar unique1 = 1;"),
            File("two.js", imports + "\n}\n}\n}\nvar unique2 = 2;"),
        ]);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VC-DUP-002");
    }

    [Fact]
    public void A_short_repeat_is_not_reported()
    {
        var few = string.Join('\n', Enumerable.Range(1, 4).Select(i => $"var s{i} = {i};"));

        var result = RedundancyChecks.Run(
            [File("one.js", few + "\nvar unique1 = 1;"), File("two.js", few + "\nvar unique2 = 2;")]);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VC-DUP-002");
    }

    [Fact]
    public void Config_and_markup_are_left_alone()
    {
        var result = RedundancyChecks.Run(
            [File("a/app.json", Block("x")), File("b/app.json", Block("x"))]);

        Assert.Empty(result.Findings);
    }

    // ---- What these findings are allowed to do -----------------------------

    /// <summary>
    /// The guarantee that keeps the score meaning what it says. A duplicated block is a
    /// maintenance cost, not a risk, and letting it move the number would turn "how dangerous
    /// is this" into "how tidy is this".
    /// </summary>
    [Fact]
    public void Every_finding_is_informational_and_cannot_move_the_score()
    {
        var result = RedundancyChecks.Run(
        [
            File("a/helpers.js", Block("x")),
            File("b/helpers.js", Block("x")),
            File("c.js", string.Join('\n',
                Enumerable.Range(1, 8).Select(i => $"// var dead{i} = go({i});"))),
        ]);

        Assert.NotEmpty(result.Findings);
        Assert.All(result.Findings, f =>
        {
            Assert.Equal(Severity.Info, f.Severity);
            Assert.Equal(Severity.Info, f.UserSeverity);
            Assert.Equal(FindingCategory.Maintainability, f.Category);
            Assert.False(f.IsBlocking);
        });
    }

    [Fact]
    public void Nothing_at_all_produces_no_findings()
    {
        var result = RedundancyChecks.Run([File("a.js", "var x = 1;\nvar y = 2;")]);

        Assert.Empty(result.Findings);
    }

    /// <summary>
    /// A scan with nothing to compare must say so, or its silence reads as a clean result.
    /// </summary>
    [Fact]
    public void An_artifact_with_no_original_source_says_it_checked_nothing()
    {
        var result = RedundancyChecks.Run([File("A.cs", Block("x"), decompiled: true)]);

        Assert.Contains(
            result.Limitations,
            l => l.Contains("No original source", StringComparison.Ordinal));
    }

    /// <summary>
    /// Distinct from the above, and worth distinguishing. A decompiled application that also
    /// ships a readable appsettings.json did yield verbatim files; none of them were code. The
    /// silence has two possible causes and only one of them is "we got nothing".
    /// </summary>
    [Fact]
    public void Verbatim_files_that_are_not_code_are_reported_as_such()
    {
        var result = RedundancyChecks.Run(
        [
            File("A.cs", Block("x"), decompiled: true),
            File("appsettings.json", "{ \"a\": 1 }"),
        ]);

        Assert.Contains(
            result.Limitations,
            l => l.Contains("were code", StringComparison.Ordinal));

        Assert.DoesNotContain(
            result.Limitations,
            l => l.Contains("No original source", StringComparison.Ordinal));
    }
}
