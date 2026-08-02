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

        Assert.Equal(97, verdict.Score);
        Assert.Equal(ScoreBand.NoKnownIssues, verdict.Band);
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
}
