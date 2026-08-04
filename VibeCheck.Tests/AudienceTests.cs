using VibeCheck.Core;
using VibeCheck.Core.Dependencies;
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
    /// The readings still disagree, and the harsher one is the score in both reports.
    /// </summary>
    /// <remarks>
    /// A leaked key is the worst thing in the report for whoever ships it and nothing at all
    /// for whoever runs it, so the two readings are genuinely different numbers. Publishing the
    /// kinder one to the reader it flatters is what this forbids: an author could otherwise
    /// scan their own work, switch reader, and screenshot a number produced for a question
    /// they were not asking.
    /// </remarks>
    [Fact]
    public void The_harsher_reading_is_the_score_in_both_reports()
    {
        var findings = new[] { Make(Severity.Critical, Severity.Info) };

        var developer = ScoreCalculator.Calculate(findings, 100, Audience.Developer);
        var endUser = ScoreCalculator.Calculate(findings, 100, Audience.EndUser);

        Assert.Equal(developer.Score, endUser.Score);
        Assert.True(developer.Score <= 39);
        Assert.Equal(ScoreBand.CriticalIssues, developer.Band);
        Assert.Equal(ScoreBand.CriticalIssues, endUser.Band);

        // Both readings survive in the account, so the difference is stated rather than lost.
        var explanation = Assert.IsType<ScoreExplanation>(endUser.Explanation);

        Assert.Equal(100, explanation.EndUserReading);
        Assert.True(explanation.DeveloperReading <= 39);
        Assert.Equal(Audience.Developer, explanation.GovernedBy);
        Assert.Contains(
            explanation.Describe(),
            line => line.Contains("switching reader", StringComparison.Ordinal));
    }

    /// <summary>
    /// The promotion direction matters as much as the demotion: the end user's reading governs
    /// whenever it is the worse of the two.
    /// </summary>
    [Fact]
    public void A_finding_worse_for_the_end_user_governs_the_developers_score_too()
    {
        var findings = new[] { Make(Severity.Medium, Severity.High) };

        var developer = ScoreCalculator.Calculate(findings, 100, Audience.Developer);
        var endUser = ScoreCalculator.Calculate(findings, 100, Audience.EndUser);

        Assert.Equal(developer.Score, endUser.Score);
        Assert.Equal(ScoreBand.SeriousIssues, developer.Band);

        // The account under the developer's number describes the reading that produced it.
        var explanation = Assert.IsType<ScoreExplanation>(developer.Explanation);

        Assert.Equal(Audience.EndUser, explanation.GovernedBy);
        Assert.Equal(Severity.High, explanation.Worst);
    }

    /// <summary>
    /// One number is only honest if it says what it is. Left captioned as an answer to the
    /// reader's own question, a score taken from the other reading would be a plain lie about
    /// which question it answered.
    /// </summary>
    [Fact]
    public void Every_verdict_says_what_its_number_is()
    {
        foreach (var audience in Enum.GetValues<Audience>())
        {
            var caption = ScoreCalculator.Calculate([], 100, audience).ScoreCaption;

            Assert.False(string.IsNullOrWhiteSpace(caption));
            Assert.Contains("shipping", caption, StringComparison.Ordinal);
            Assert.Contains("running", caption, StringComparison.Ordinal);
        }

        // The same caption in both reports, because it is the same number.
        Assert.Equal(
            ScoreCalculator.Calculate([], 100, Audience.Developer).ScoreCaption,
            ScoreCalculator.Calculate([], 100, Audience.EndUser).ScoreCaption);
    }

    /// <summary>
    /// The findings still differ, which is the half of the split that survives. Only the number
    /// is shared.
    /// </summary>
    [Fact]
    public void The_reports_still_disagree_about_what_the_findings_mean()
    {
        var findings = new[] { Make(Severity.Critical, Severity.Info) };

        Assert.Equal(Severity.Critical, findings[0].SeverityFor(Audience.Developer));
        Assert.Equal(Severity.Info, findings[0].SeverityFor(Audience.EndUser));

        Assert.NotEqual(
            findings[0].DescriptionFor(Audience.Developer),
            findings[0].DescriptionFor(Audience.EndUser));
    }

    /// <summary>
    /// The category breakdown takes the same rule as the headline, or the same screenshot
    /// could be taken one card further down the report.
    /// </summary>
    [Fact]
    public void The_category_breakdown_cannot_be_softened_by_switching_reader()
    {
        var findings = new[] { Make(Severity.Critical, Severity.Info) };

        var scores = ScoreCalculator.CategoryScores(findings);

        Assert.True(scores[FindingCategory.Secrets] <= 39);
    }

    /// <summary>
    /// The consequence of a shared number that has to be said out loud rather than left for a
    /// reader to trip over: the score can be in the critical band on findings that are all
    /// informational for whoever is reading, and the line under it must not then claim nothing
    /// was found.
    /// </summary>
    [Fact]
    public void A_report_with_nothing_for_this_reader_does_not_claim_nothing_was_found()
    {
        var report = Report([Make(Severity.Critical, Severity.Info)], Audience.EndUser);

        Assert.Equal(ScoreBand.CriticalIssues, report.Verdict.Band);
        Assert.Equal(0, report.CountOf(Severity.Critical));

        Assert.DoesNotContain("No issues were found", report.SummaryLine, StringComparison.Ordinal);
        Assert.Contains("1 finding", report.SummaryLine, StringComparison.Ordinal);

        // And the same sentence reaches the exported copy, rather than the two drifting apart.
        Assert.Contains(report.SummaryLine, MarkdownReportWriter.Write(report), StringComparison.Ordinal);
    }

    /// <summary>A scan that really found nothing still says so plainly.</summary>
    [Fact]
    public void A_report_with_no_findings_at_all_still_says_so()
    {
        foreach (var audience in Enum.GetValues<Audience>())
        {
            Assert.Equal(
                "No issues were found by the checks that ran.",
                Report([], audience).SummaryLine);
        }
    }

    /// <summary>
    /// The case this exists for: a shipped application with no lock file scores 100 under "no
    /// known issues found", beside a coverage meter reading 100% readable, while nothing at all
    /// is known about the packages inside it.
    /// </summary>
    [Fact]
    public void A_class_of_check_that_could_not_run_is_said_beside_the_score()
    {
        var report = Report([], Audience.EndUser) with
        {
            Effort = Effort(resolved: 0, checkedCount: 0, unresolved: 1),
        };

        Assert.Equal(100, report.Verdict.Score);
        Assert.NotNull(report.DependencyCaveat);
        Assert.Contains("Nothing is known", report.DependencyCaveat, StringComparison.Ordinal);

        // And it reaches the exported copy, next to the number rather than four sections later.
        var markdown = MarkdownReportWriter.Write(report);
        var verdict = markdown.IndexOf("100/100", StringComparison.Ordinal);
        var caveat = markdown.IndexOf("Not everything could be checked", StringComparison.Ordinal);

        Assert.True(caveat > verdict, "the caveat must follow the score");
        Assert.True(caveat - verdict < 600, $"and sit beside it, not {caveat - verdict} characters later");
    }

    /// <summary>Resolved but unanswered is a different sentence from never resolved.</summary>
    [Fact]
    public void Dependencies_resolved_but_never_looked_up_say_so()
    {
        var report = Report([], Audience.Developer) with
        {
            Effort = Effort(resolved: 12, checkedCount: 0, unresolved: 0),
        };

        Assert.Contains("12 dependencies", report.DependencyCaveat!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Silent when nothing was skipped. An application that declares no dependencies has no gap
    /// to warn about, and one whose dependencies were checked has nothing to apologise for.
    /// </summary>
    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(9, 9, 0)]
    public void No_caveat_when_nothing_was_missed(int resolved, int checkedCount, int unresolved) =>
        Assert.Null((Report([], Audience.Developer) with
        {
            Effort = Effort(resolved, checkedCount, unresolved),
        }).DependencyCaveat);

    private static ScanEffort Effort(int resolved, int checkedCount, int unresolved) => new()
    {
        RecoveryMethod = "test",
        FilesRecovered = 1,
        BytesRecovered = 1,
        ChecksRun = 1,
        FilesChecked = 1,
        PackagesResolved = resolved,
        PackagesChecked = checkedCount,
        ManifestsUnresolved = unresolved,
        VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
    };

    private static ScanReport Report(IReadOnlyList<Finding> findings, Audience audience) => new()
    {
        ArtifactName = "test",
        Kind = ArtifactKind.SourceTree,
        ArtifactBytes = 1,
        Sha256 = new string('0', 64),
        ScannedAt = DateTimeOffset.UnixEpoch,
        Verdict = ScoreCalculator.Calculate(findings, 100, audience),
        Coverage = new CoverageReport { Percent = 100, Basis = "test" },
        Findings = findings,
        CategoryScores = ScoreCalculator.CategoryScores(findings),
        VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
        Effort = new ScanEffort
        {
            RecoveryMethod = "test",
            FilesRecovered = 1,
            BytesRecovered = 1,
            ChecksRun = 1,
            FilesChecked = 1,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
        },
        Checks = new CheckSummary(),
        ScannerVersion = "test",
        Duration = TimeSpan.FromSeconds(1),
    };

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
            Assert.Contains("not your problem", endUserText, StringComparison.OrdinalIgnoreCase);

            // One number, and both reports say so in the same words.
            Assert.Equal(developer.Verdict.Score, endUser.Verdict.Score);
            Assert.Contains(Verdict.SharedScoreCaption, developerText, StringComparison.Ordinal);
            Assert.Contains(Verdict.SharedScoreCaption, endUserText, StringComparison.Ordinal);
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
