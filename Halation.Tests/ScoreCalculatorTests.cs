using VibeCheck.Core.Model;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Tests;

public class ScoreCalculatorTests
{
    private static Finding Make(
        Severity severity,
        FindingCategory category = FindingCategory.CodeSafety,
        bool blocking = false,
        FindingSource source = FindingSource.Rule,
        Severity? userSeverity = null) => new()
    {
        RuleId = $"VC-TEST-{severity}",
        Title = $"{severity} test finding",
        Severity = severity,
        UserSeverity = userSeverity ?? severity,
        Category = category,
        Description = "Synthetic finding used by the scoring tests.",
        UserDescription = "Synthetic finding as told to someone running the application.",
        IsBlocking = blocking,
        Source = source,
    };

    [Fact]
    public void CleanScan_ScoresFullMarks()
    {
        var verdict = ScoreCalculator.Calculate([]);

        Assert.Equal(100, verdict.Score);
        Assert.Equal(ScoreBand.NoKnownIssues, verdict.Band);
        Assert.False(verdict.AdviseAgainstInstall);
    }

    /// <summary>
    /// The failure mode the cap exists to prevent: an app whose only problem is severe
    /// must not be rescued by everything else passing.
    /// </summary>
    [Fact]
    public void SingleCritical_CapsScoreIntoRedBand()
    {
        var verdict = ScoreCalculator.Calculate([Make(Severity.Critical)]);

        Assert.True(verdict.Score <= 39, $"expected <= 39, got {verdict.Score}");
        Assert.Equal(ScoreBand.CriticalIssues, verdict.Band);
    }

    [Theory]
    [InlineData(Severity.Critical, 39)]
    [InlineData(Severity.High, 69)]
    [InlineData(Severity.Medium, 89)]
    public void WorstFinding_DictatesCeiling(Severity worst, int ceiling)
    {
        var verdict = ScoreCalculator.Calculate([Make(worst)]);

        Assert.True(
            verdict.Score <= ceiling,
            $"{worst} should cap at {ceiling}, got {verdict.Score}");
    }

    [Fact]
    public void LowSeverityAlone_StaysInTopBand()
    {
        var verdict = ScoreCalculator.Calculate([Make(Severity.Low)]);

        Assert.InRange(verdict.Score, 90, 99);
        Assert.Equal(ScoreBand.NoKnownIssues, verdict.Band);
    }

    // ---- The floor -----------------------------------------------------------

    /// <summary>
    /// The correction to the old model. Deductions used to subtract from 100 and clamp at
    /// zero, so three critical findings and forty produced the same number, and that number
    /// told the reader nothing measured about the application was acceptable. No static scan
    /// can know that, and an author whose app scores zero has been told something untrue.
    /// </summary>
    [Fact]
    public void ManyCriticals_DoNotBottomOutAtZero()
    {
        var verdict = ScoreCalculator.Calculate(
            [.. Enumerable.Repeat(Make(Severity.Critical), 40)]);

        Assert.True(verdict.Score >= 10, $"expected a floor of 10, got {verdict.Score}");
        Assert.Equal(ScoreBand.CriticalIssues, verdict.Band);
    }

    /// <summary>
    /// The number has to keep meaning something at the bad end. Saturating means an
    /// application with three critical findings and one with forty read identically, which is
    /// where the difference matters most.
    /// </summary>
    [Fact]
    public void MoreCriticals_AlwaysScoreBelowFewer()
    {
        var three = ScoreCalculator.Calculate(
            [.. Enumerable.Repeat(Make(Severity.Critical), 3)]).Score;

        var twenty = ScoreCalculator.Calculate(
            [.. Enumerable.Repeat(Make(Severity.Critical), 20)]).Score;

        Assert.True(twenty < three, $"20 criticals scored {twenty}, 3 scored {three}");
    }

    /// <summary>
    /// The band label must never name a severity the scan did not find. Under the old model
    /// five high findings scored zero and were reported as "critical issues", which invented
    /// a severity that was not there.
    /// </summary>
    [Theory]
    [InlineData(Severity.High, ScoreBand.SeriousIssues)]
    [InlineData(Severity.Medium, ScoreBand.NeedsWork)]
    public void ManyFindings_NeverEscalateTheBandBeyondTheWorstFinding(
        Severity worst,
        ScoreBand expected)
    {
        var verdict = ScoreCalculator.Calculate([.. Enumerable.Repeat(Make(worst), 25)]);

        Assert.Equal(expected, verdict.Band);
    }

    /// <summary>
    /// Informational findings are listed but weightless, and the report says so. If they moved
    /// the number, "no score impact" would be a false statement in the report.
    /// </summary>
    [Fact]
    public void InformationalFindings_DoNotMoveTheScore()
    {
        var verdict = ScoreCalculator.Calculate([.. Enumerable.Repeat(Make(Severity.Info), 30)]);

        Assert.Equal(100, verdict.Score);
        Assert.Equal(30, verdict.Explanation?.Informational);
        Assert.Equal(0, verdict.Explanation?.Counted);
    }

    /// <summary>A number nobody can account for is a number nobody trusts.</summary>
    [Fact]
    public void TheScore_ExplainsItself()
    {
        var verdict = ScoreCalculator.Calculate(
            [Make(Severity.Critical), Make(Severity.Low), Make(Severity.Info)]);

        var explanation = Assert.IsType<ScoreExplanation>(verdict.Explanation);

        Assert.Equal(Severity.Critical, explanation.Worst);
        Assert.Equal(10, explanation.Floor);
        Assert.Equal(39, explanation.Ceiling);
        Assert.Equal(2, explanation.Counted);
        Assert.Equal(1, explanation.Informational);
        Assert.NotEmpty(explanation.Describe());
    }

    [Fact]
    public void MultipleFindings_CompoundBeyondTheCap()
    {
        var one = ScoreCalculator.Calculate([Make(Severity.High)]).Score;
        var many = ScoreCalculator.Calculate([
            Make(Severity.High), Make(Severity.High), Make(Severity.High),
        ]).Score;

        Assert.True(many < one, "three highs should score worse than one");
    }

    [Fact]
    public void ScoreNeverLeavesRange()
    {
        var findings = Enumerable.Range(0, 50).Select(_ => Make(Severity.Critical)).ToList();

        var verdict = ScoreCalculator.Calculate(findings);

        Assert.InRange(verdict.Score, 0, 100);
    }

    [Fact]
    public void BandAlwaysAgreesWithScore()
    {
        // Every severity combination up to three findings; the band must never contradict
        // the number, which is what lets the UI show them together without caveats.
        var severities = Enum.GetValues<Severity>();

        foreach (var a in severities)
        {
            foreach (var b in severities)
            {
                var verdict = ScoreCalculator.Calculate([Make(a), Make(b)]);
                var expected = verdict.Score switch
                {
                    <= 39 => ScoreBand.CriticalIssues,
                    <= 69 => ScoreBand.SeriousIssues,
                    <= 89 => ScoreBand.NeedsWork,
                    _ => ScoreBand.NoKnownIssues,
                };

                Assert.Equal(expected, verdict.Band);
            }
        }
    }

    [Fact]
    public void BlockingRuleFinding_AdvisesAgainstInstall()
    {
        var verdict = ScoreCalculator.Calculate([Make(Severity.Critical, blocking: true)]);

        Assert.True(verdict.AdviseAgainstInstall);
        Assert.Single(verdict.BlockingReasons);
    }

    /// <summary>
    /// The strongest claim in the report must not depend on whether the user supplied an
    /// API key, so an inferred finding can never block installation however severe it is.
    /// </summary>
    [Fact]
    public void BlockingAssistedFinding_DoesNotAdviseAgainstInstall()
    {
        var verdict = ScoreCalculator.Calculate([
            Make(Severity.Critical, blocking: true, source: FindingSource.Assisted),
        ]);

        Assert.False(verdict.AdviseAgainstInstall);
        Assert.Empty(verdict.BlockingReasons);
    }

    [Fact]
    public void CategoryScores_IsolateByCategory()
    {
        var scores = ScoreCalculator.CategoryScores([
            Make(Severity.Critical, FindingCategory.Secrets),
        ]);

        Assert.True(scores[FindingCategory.Secrets] <= 39);
        Assert.Equal(100, scores[FindingCategory.Network]);
        Assert.Equal(100, scores[FindingCategory.Auth]);
    }

    [Fact]
    public void CategoryScores_CoverEveryCategory()
    {
        var scores = ScoreCalculator.CategoryScores([]);

        Assert.Equal(Enum.GetValues<FindingCategory>().Length, scores.Count);
    }

    // ---- The deep pass reports; it does not score --------------------------

    /// <summary>
    /// The whole reason for the rule. Measured on one unchanged application: the rules said 99
    /// every time, a local 7B model made it 41 and Opus 5 made it 75. A number that moves with
    /// the reader's choice of model cannot be compared with anybody else's.
    /// </summary>
    [Fact]
    public void Inferred_findings_do_not_move_the_number()
    {
        var rulesOnly = ScoreCalculator.Calculate([Make(Severity.Low)]);

        var withDeepPass = ScoreCalculator.Calculate(
        [
            Make(Severity.Low),
            Make(Severity.Critical, source: FindingSource.Assisted),
            Make(Severity.High, source: FindingSource.Assisted),
            Make(Severity.High, source: FindingSource.Assisted),
        ]);

        Assert.Equal(rulesOnly.Score, withDeepPass.Score);
        Assert.Equal(rulesOnly.Band, withDeepPass.Band);
    }

    /// <summary>
    /// And the other half, without which the first half is a licence to publish a clean headline
    /// over a real problem: the label may not claim the all-clear while they exist.
    /// </summary>
    [Fact]
    public void The_top_band_may_not_claim_a_clean_result_while_inferred_findings_exist()
    {
        var verdict = ScoreCalculator.Calculate(
            [Make(Severity.Medium, source: FindingSource.Assisted)]);

        // Nothing deterministic was found, so the arithmetic genuinely has nothing to count.
        Assert.Equal(100, verdict.Score);
        Assert.Equal(ScoreBand.NoKnownIssues, verdict.Band);

        // But the words beside it must not say so. Counted, so the label agrees with itself:
        // one finding used to be announced as "1 AI suggestions to review".
        Assert.NotEqual("No known issues found", verdict.BandLabel);
        Assert.Contains("1 AI suggestion to review", verdict.BandLabel, StringComparison.Ordinal);

        // The reader's own setup is never ranked inside their own report. Which model answered
        // is on the receipt; a sentence beside the score saying results vary by model reads as
        // "yours may be the worse one", and turns a fact about the tool into doubt about the
        // document.
        Assert.DoesNotContain("varies", verdict.InferredSummary!, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(1, verdict.InferredCount);
        Assert.Equal(Severity.Medium, verdict.WorstInferred);
        Assert.NotNull(verdict.InferredSummary);
    }

    [Fact]
    public void Weightless_inferred_findings_raise_no_caveat()
    {
        // An inferred finding that deducts nothing on either reading has nothing to qualify, and
        // a caveat printed on every report stops being read. Same rule as the dependency caveat.
        var verdict = ScoreCalculator.Calculate(
            [Make(Severity.Info, source: FindingSource.Assisted)]);

        Assert.Equal(0, verdict.InferredCount);
        Assert.Equal("No known issues found", verdict.BandLabel);
        Assert.Null(verdict.InferredSummary);
    }

    [Fact]
    public void Category_scores_ignore_inferred_findings_too()
    {
        // Otherwise the same screenshot is available one card further down: a category reading
        // worse than the headline that governs it.
        var scores = ScoreCalculator.CategoryScores(
        [
            Make(Severity.Critical, FindingCategory.CodeSafety, source: FindingSource.Assisted),
        ]);

        Assert.Equal(100, scores[FindingCategory.CodeSafety]);
    }

    [Fact]
    public void The_account_of_the_number_counts_only_what_produced_it()
    {
        // The explanation is read against the number directly above it. Counting inferred
        // findings there would describe arithmetic that never ran.
        var verdict = ScoreCalculator.Calculate(
        [
            Make(Severity.Medium),
            Make(Severity.Critical, source: FindingSource.Assisted),
        ]);

        Assert.NotNull(verdict.Explanation);
        Assert.Equal(Severity.Medium, verdict.Explanation!.Worst);
        Assert.Equal(1, verdict.Explanation.Counted);
    }
}
