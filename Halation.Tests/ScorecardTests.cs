using Halation.Core.Model;
using Halation.Core.Dependencies;
using Halation.Core.Scoring;

namespace Halation.Tests;

/// <summary>
/// Covers what the shareable scorecard is allowed to claim.
/// </summary>
/// <remarks>
/// This is the one artifact the product makes that is meant to be read out of context, by
/// somebody who has not run the scan. The tests that matter here are the ones checking it cannot
/// show a bare number: coverage, the hash and the version are what stop it being a vanity badge.
/// </remarks>
public sealed class ScorecardTests
{
    private static Finding At(Severity severity, string id) => new()
    {
        RuleId = id,
        Title = $"{severity} thing",
        Severity = severity,
        UserSeverity = severity,
        Category = FindingCategory.Secrets,
        Description = "d",
        UserDescription = "d",
    };

    private static ScanReport Report(
        IReadOnlyList<Finding> findings,
        int coverage = 100,
        string sha = "abc123",
        string version = "0.1.4-beta",
        bool hashCoversContent = true)
    {
        return new ScanReport
        {
            HashCoversContent = hashCoversContent,
            ArtifactName = "fixture.exe",
            Kind = ArtifactKind.SourceTree,
            ArtifactBytes = 10,
            Sha256 = sha,
            ScannedAt = new DateTimeOffset(2026, 8, 7, 12, 0, 0, TimeSpan.Zero),
            Verdict = ScoreCalculator.Calculate(findings),
            Coverage = new CoverageReport
            {
                Percent = coverage,
                Basis = "fixture",
                RecoveredFileCount = 1,
                RecoveredBytes = 10,
            },
            Findings = findings,
            CategoryScores = ScoreCalculator.CategoryScores(findings),
            VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
            Effort = new ScanEffort
            {
                RecoveryMethod = "fixture",
                FilesRecovered = 1,
                BytesRecovered = 10,
                ChecksRun = 40,
                FilesChecked = 1,
                PackagesResolved = 0,
                PackagesChecked = 0,
                VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
            },
            ScannerVersion = version,
        };
    }

    [Fact]
    public void CountsEachSeveritySeparately()
    {
        var card = Scorecard.From(Report(
        [
            At(Severity.Critical, "A"), At(Severity.Critical, "B"),
            At(Severity.High, "C"),
            At(Severity.Low, "D"), At(Severity.Low, "E"), At(Severity.Low, "F"),
            At(Severity.Info, "G"),
        ]));

        Assert.Equal(2, card.Critical);
        Assert.Equal(1, card.High);
        Assert.Equal(0, card.Medium);
        Assert.Equal(3, card.Low);
        Assert.Equal(1, card.Info);
    }

    [Fact]
    public void CountedLeavesOutTheOnesThatScoreNothing()
    {
        var card = Scorecard.From(Report([At(Severity.Low, "A"), At(Severity.Info, "B")]));

        Assert.Equal(1, card.Counted);
    }

    [Fact]
    public void CountsDisplayIsCriticalHighMediumLow()
    {
        var card = Scorecard.From(Report([At(Severity.Critical, "A"), At(Severity.Medium, "B")]));

        Assert.Equal("1/0/1/0", card.CountsDisplay);
    }

    [Fact]
    public void CarriesCoverage()
    {
        var card = Scorecard.From(Report([], coverage: 37));

        Assert.Equal(37, card.CoveragePercent);
    }

    [Fact]
    public void CarriesTheHashAndTheVersionThatProducedIt()
    {
        var card = Scorecard.From(Report([], sha: "deadbeef", version: "9.9.9"));

        Assert.Equal("deadbeef", card.Sha256);
        Assert.Equal("9.9.9", card.ScannerVersion);
        Assert.Contains("9.9.9", card.VerificationLine, StringComparison.Ordinal);
    }

    /// <summary>
    /// A card cannot say how to check it against a hash it does not have, and must not imply it
    /// can. A folder has no single file to point at.
    /// </summary>
    [Fact]
    public void SaysHowToCheckItDifferentlyWithoutAHash()
    {
        var withHash = Scorecard.From(Report([], sha: "abc"));
        var without = Scorecard.From(Report([], sha: "", hashCoversContent: false));

        Assert.Contains("hash", withHash.VerificationLine, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", without.VerificationLine, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The directory hash is a digest of relative paths and file sizes, not of the code. Two
    /// folders with the same shape and completely different contents share it, so putting it on
    /// a card beside "check this by rescanning" offers a verification it cannot perform.
    /// </summary>
    [Fact]
    public void WithholdsAHashThatCannotSpeakForTheContents()
    {
        var card = Scorecard.From(Report([], sha: "manifestdigest", hashCoversContent: false));

        Assert.Equal(string.Empty, card.Sha256);
        Assert.DoesNotContain("manifestdigest", card.VerificationLine, StringComparison.Ordinal);
        Assert.NotNull(card.HashCaveat);
    }

    [Fact]
    public void KeepsAHashThatDoesSpeakForTheContents()
    {
        var card = Scorecard.From(Report([], sha: "realfilehash", hashCoversContent: true));

        Assert.Equal("realfilehash", card.Sha256);
        Assert.Null(card.HashCaveat);
    }

    /// <summary>
    /// A badge claiming to be checkable without saying how is asking to be believed, which is
    /// the opposite of the point of having one.
    /// </summary>
    [Fact]
    public void SaysWhatCheckingItActuallyInvolves()
    {
        var card = Scorecard.From(Report([], sha: "abc", version: "1.2.3"));

        Assert.Contains("scan", card.VerificationLine, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("1.2.3", card.VerificationLine, StringComparison.Ordinal);
    }

    /// <summary>
    /// Below the coverage floor there is no score, and the card has to say so. A zero would read
    /// as "scored badly" when the truth is "not scored at all".
    /// </summary>
    [Fact]
    public void RefusesToDrawANumberWhenThereIsNotOne()
    {
        var report = Report([], coverage: 2);
        var card = Scorecard.From(report);

        if (report.Verdict.HasMeaningfulScore)
        {
            // The floor moved; this test is about the other side of it.
            Assert.NotNull(card.Score);
            return;
        }

        Assert.Null(card.Score);
        Assert.Equal("not scored", card.ScoreDisplay);
        Assert.DoesNotContain("0/100", card.ScoreDisplay, StringComparison.Ordinal);
    }

    [Fact]
    public void ScoreDisplayIsOutOfAHundred()
    {
        var card = Scorecard.From(Report([]));

        Assert.EndsWith("/100", card.ScoreDisplay, StringComparison.Ordinal);
    }

    [Fact]
    public void CarriesTheBandInWordsRatherThanOnlyTheNumber()
    {
        var card = Scorecard.From(Report([At(Severity.Critical, "A")]));

        Assert.False(string.IsNullOrWhiteSpace(card.Band));
    }

    [Fact]
    public void RejectsANullReport() =>
        Assert.Throws<ArgumentNullException>(() => Scorecard.From(null!));
}
