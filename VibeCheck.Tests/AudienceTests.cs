using VibeCheck.Core;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;
using VibeCheck.Core.Rules;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Tests;

/// <summary>
/// The report answers one of two questions, and which one it answered has to be visible.
/// These cover the split itself rather than any individual rule's judgment: that the two
/// audiences can genuinely disagree, that the disagreement is labelled, and that the
/// guarantees which were true of one score stay true of both.
/// </summary>
public class AudienceTests
{
    private static Finding Make(
        Severity developer,
        Severity user,
        bool blocking = false,
        FindingSource source = FindingSource.Rule) => new()
    {
        RuleId = "VC-TEST-001",
        Title = "test finding",
        Severity = developer,
        UserSeverity = user,
        Category = FindingCategory.Secrets,
        Description = "As told to the person who wrote it.",
        UserDescription = "As told to the person running it.",
        IsBlocking = blocking,
        Source = source,
    };

    /// <summary>
    /// The case the whole feature exists for. A leaked key is the worst thing in the report
    /// for the person shipping it and nothing at all for the person running it, so a single
    /// number cannot serve both.
    /// </summary>
    [Fact]
    public void The_same_finding_can_score_differently_for_each_reader()
    {
        var findings = new[] { Make(Severity.Critical, Severity.Info) };

        var developer = ScoreCalculator.Calculate(findings, 100, Audience.Developer);
        var endUser = ScoreCalculator.Calculate(findings, 100, Audience.EndUser);

        Assert.Equal(ScoreBand.CriticalIssues, developer.Band);
        Assert.True(developer.Score <= 39);

        Assert.Equal(ScoreBand.NoKnownIssues, endUser.Band);
        Assert.Equal(100, endUser.Score);
    }

    /// <summary>The promotion direction matters as much as the demotion.</summary>
    [Fact]
    public void A_finding_can_be_worse_for_the_end_user_than_for_the_developer()
    {
        var findings = new[] { Make(Severity.Medium, Severity.High) };

        Assert.True(
            ScoreCalculator.Calculate(findings, 100, Audience.EndUser).Score
            < ScoreCalculator.Calculate(findings, 100, Audience.Developer).Score);
    }

    /// <summary>
    /// Two numbers are only honest if each says what it answered. An unlabelled score that
    /// changes with a setting is worse than either score on its own.
    /// </summary>
    [Fact]
    public void Every_verdict_states_which_question_it_answered()
    {
        foreach (var audience in Enum.GetValues<Audience>())
        {
            var caption = ScoreCalculator.Calculate([], 100, audience).ScoreCaption;

            Assert.False(string.IsNullOrWhiteSpace(caption));
            Assert.Contains("Risk", caption, StringComparison.Ordinal);
        }

        Assert.NotEqual(
            ScoreCalculator.Calculate([], 100, Audience.Developer).ScoreCaption,
            ScoreCalculator.Calculate([], 100, Audience.EndUser).ScoreCaption);
    }

    /// <summary>
    /// Blocking is about danger to the person installing, so it must not weaken just because
    /// the developer's severity was lowered for their own view.
    /// </summary>
    [Fact]
    public void Blocking_survives_in_both_views()
    {
        var findings = new[] { Make(Severity.Critical, Severity.Critical, blocking: true) };

        foreach (var audience in Enum.GetValues<Audience>())
        {
            var verdict = ScoreCalculator.Calculate(findings, 100, audience);

            Assert.True(verdict.AdviseAgainstInstall);
            Assert.NotEmpty(verdict.BlockingReasons);
        }
    }

    /// <summary>
    /// The deep pass still cannot make the strongest claim in the report, in either view.
    /// </summary>
    [Fact]
    public void An_assisted_finding_never_blocks_in_either_view()
    {
        var findings = new[]
        {
            Make(Severity.Critical, Severity.Critical, blocking: true, source: FindingSource.Assisted),
        };

        foreach (var audience in Enum.GetValues<Audience>())
        {
            Assert.False(ScoreCalculator.Calculate(findings, 100, audience).AdviseAgainstInstall);
        }
    }

    /// <summary>
    /// The coverage gate is about how much was read, which has nothing to do with who is
    /// reading, so it cannot be escaped by switching audience.
    /// </summary>
    [Fact]
    public void The_coverage_gate_applies_to_both_views()
    {
        foreach (var audience in Enum.GetValues<Audience>())
        {
            var verdict = ScoreCalculator.Calculate([], 1, audience);

            Assert.Equal(ScoreBand.InsufficientCoverage, verdict.Band);
            Assert.False(verdict.HasMeaningfulScore);
            Assert.Equal("Not scored", verdict.ScoreDisplay);
        }
    }

    /// <summary>
    /// Every rule in the catalog has to have had the judgment made, because the alternative
    /// is filing the developer's problems as the end user's by default. The type system
    /// enforces this; the test states it, so removing the requirement is a visible act.
    /// </summary>
    [Fact]
    public void Every_rule_carries_a_judgment_for_both_readers()
    {
        var rules = new RuleEngine().Rules.OfType<PatternRule>().ToList();

        Assert.NotEmpty(rules);

        foreach (var rule in rules)
        {
            Assert.False(
                string.IsNullOrWhiteSpace(rule.UserDescription),
                $"{rule.Id} has no end-user description");

            // Not a translation of the developer's text. Sharing the string would mean the
            // reader is being handed remediation they cannot perform and jargon they cannot use.
            Assert.NotEqual(rule.Description, rule.UserDescription);
        }
    }

    /// <summary>
    /// Switching reader re-answers the report in hand rather than rescanning, so the two views
    /// can disagree about what a finding means but never about what was found.
    /// </summary>
    [Fact]
    public async Task Switching_reader_rescores_without_changing_the_findings()
    {
        var root = Path.Combine(Path.GetTempPath(), "vc-aud-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            // A leaked key and a shell-opened link: one demotes for the end user, one promotes.
            File.WriteAllText(Path.Combine(root, "app.js"), """
                const key = "sk_live_4eC39HqLyjWDarjtT1zdp7dcabcd";
                function open(u) { require("child_process").exec("start " + u); }
                """);

            var developer = await new Scanner().ScanAsync(
                root,
                ScanOptions.NoDependencyCheck with { Audience = Audience.Developer });

            var endUser = Scanner.Rescore(developer, Audience.EndUser);

            Assert.Equal(Audience.Developer, developer.Audience);
            Assert.Equal(Audience.EndUser, endUser.Audience);

            // Same evidence, different answer.
            Assert.Equal(developer.Findings, endUser.Findings);

            // Re-answering for the reader it already answers is a no-op, not a recalculation.
            Assert.Same(endUser, Scanner.Rescore(endUser, Audience.EndUser));

            // The two documents differ in what they carry, not only in how they read. The rule
            // identifier is a support handle for whoever can act on it and a serial number
            // attached to anxiety for whoever cannot.
            var developerText = MarkdownReportWriter.Write(developer);
            var endUserText = MarkdownReportWriter.Write(endUser);

            Assert.Contains("VC-SEC-", developerText, StringComparison.Ordinal);
            Assert.DoesNotContain("VC-SEC-", endUserText, StringComparison.Ordinal);

            Assert.Contains("How to fix", developerText, StringComparison.Ordinal);
            Assert.Contains("Risk to you in running this", endUserText, StringComparison.Ordinal);
            Assert.Contains("not your problem", endUserText, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    /// <summary>
    /// The end user's copy must not carry the identifiers that are meaningless to them. This
    /// is the specific thing that makes the two reports different documents rather than one
    /// document in two fonts.
    /// </summary>
    [Fact]
    public void The_end_user_wording_avoids_developer_jargon()
    {
        string[] jargon = ["CVE-", "CWE-", "row-level security", "Authenticode", "stdout"];

        foreach (var rule in new RuleEngine().Rules.OfType<PatternRule>())
        {
            foreach (var term in jargon)
            {
                Assert.DoesNotContain(term, rule.UserDescription, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
}
