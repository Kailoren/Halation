using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Rules;

namespace Halation.Tests;

/// <summary>
/// The report now shows what passed, not only what failed. That is worth having, and it is
/// also the most dangerous kind of thing to add: a pass claimed for a check that never ran
/// turns "we found nothing" into "we looked and it was fine", which is the exact mistake that
/// once produced a confident 100/100 on an application that had been read almost not at all.
/// </summary>
public class CheckOutcomeTests
{
    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    private static PatternRule Rule(
        string id,
        string pattern,
        SourceLanguage? language = null) => new()
    {
        Id = id,
        Title = $"test rule {id}",
        Severity = Severity.Medium,
        UserSeverity = Severity.Low,
        Category = FindingCategory.CodeSafety,
        Description = "x",
        UserDescription = "x",
        Remediation = "x",
        Pattern = PatternRule.Compile(pattern),
        Languages = language is null ? null : [language.Value],
    };

    [Fact]
    public void A_rule_that_ran_and_found_nothing_is_a_pass()
    {
        var result = new RuleEngine([Rule("VC-T-001", "neverappears")])
            .Analyse([File("a.cs", "int x = 1;")]);

        var check = Assert.Single(result.Checks);
        Assert.Equal(CheckState.Passed, check.State);
        Assert.Equal(1, check.FilesExamined);
    }

    [Fact]
    public void A_rule_that_fired_is_reported_as_having_found_something()
    {
        var result = new RuleEngine([Rule("VC-T-002", "danger")])
            .Analyse([File("a.cs", "var danger = true;")]);

        var check = Assert.Single(result.Checks);
        Assert.Equal(CheckState.FoundIssues, check.State);
    }

    /// <summary>
    /// The state that must exist. A rule with nothing to run against has not passed, and
    /// rendering it as a tick would claim ground the scan never covered.
    /// </summary>
    [Fact]
    public void A_rule_with_nothing_to_run_against_is_not_a_pass()
    {
        var result = new RuleEngine([Rule("VC-T-003", "danger", language: SourceLanguage.Python)])
            .Analyse([File("a.cs", "var danger = true;")]);

        var check = Assert.Single(result.Checks);
        Assert.Equal(CheckState.NotChecked, check.State);
        Assert.Equal(0, check.FilesExamined);
    }

    /// <summary>
    /// The headline case: an artifact that yielded no readable source must not produce a wall
    /// of green ticks.
    /// </summary>
    [Fact]
    public void A_scan_that_recovered_nothing_passes_no_checks()
    {
        var result = new RuleEngine([Rule("VC-T-004", "danger"), Rule("VC-T-005", "other")])
            .Analyse([]);

        Assert.All(result.Checks, c => Assert.Equal(CheckState.NotChecked, c.State));
        Assert.Equal(0, new CheckSummary { Checks = result.Checks }.Passed);
    }

    [Fact]
    public void The_pass_records_how_many_files_it_was_worth()
    {
        var result = new RuleEngine([Rule("VC-T-006", "neverappears")])
            .Analyse([File("a.cs", "x"), File("b.cs", "y"), File("c.cs", "z")]);

        Assert.Equal(3, Assert.Single(result.Checks).FilesExamined);
    }

    /// <summary>Any two of the three counts without the third mislead in one direction.</summary>
    [Fact]
    public void The_summary_states_all_three_counts()
    {
        var result = new RuleEngine(
            [
                Rule("VC-T-007", "danger"),
                Rule("VC-T-008", "neverappears"),
                Rule("VC-T-009", "danger", language: SourceLanguage.Python),
            ])
            .Analyse([File("a.cs", "var danger = true;")]);

        var summary = new CheckSummary { Checks = result.Checks };

        Assert.Equal(1, summary.FoundIssues);
        Assert.Equal(1, summary.Passed);
        Assert.Equal(1, summary.NotChecked);

        var described = summary.Describe();

        Assert.Contains("1 check passed", described, StringComparison.Ordinal);
        Assert.Contains("1 found something", described, StringComparison.Ordinal);
        Assert.Contains("1 could not run", described, StringComparison.Ordinal);
    }

    /// <summary>Every rule in the shipped catalog can name itself in the list.</summary>
    [Fact]
    public void Every_shipped_rule_has_a_title()
    {
        Assert.All(RuleEngine.DefaultRules, rule =>
            Assert.False(string.IsNullOrWhiteSpace(rule.Title), $"{rule.Id} has no title"));
    }
}
