using System.Text.Json;

using Halation.Core.Dependencies;
using Halation.Core.Model;
using Halation.Core.Reporting;
using Halation.Core.Scoring;

namespace Halation.Tests;

/// <summary>
/// Small things the exports got wrong, each of which a reader would have had to take on trust.
/// </summary>
/// <remarks>
/// All three were found by reading a real report rather than by a failing test, which is why
/// they are pinned here: none of them breaks anything, and all of them are the report saying
/// something that is not so.
/// </remarks>
public class ExportDetailTests
{
    private static ScanReport Report(
        VulnerabilityDataProvenance provenance,
        params Finding[] findings) => new()
    {
        ArtifactName = "app.zip",
        Kind = ArtifactKind.ElectronApp,
        ArtifactBytes = 2048,
        Sha256 = new string('b', 64),
        ScannedAt = DateTimeOffset.Now,
        Verdict = ScoreCalculator.Calculate(findings, 100, Audience.Developer, []),
        Coverage = new CoverageReport { Percent = 100, Basis = "read it all" },
        Findings = findings,
        CategoryScores = new Dictionary<FindingCategory, int>(),
        VulnerabilityData = provenance,
        Effort = new ScanEffort
        {
            RecoveryMethod = "unpacking the asar archive",
            FilesRecovered = 5,
            BytesRecovered = 1000,
            ChecksRun = 40,
            FilesChecked = 5,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = provenance,
        },
        ScannerVersion = "0.1.6-beta",
    };

    private static Finding Informational => new()
    {
        RuleId = "VC-DUP-002",
        Title = "A block of 8+ lines repeats within one file",
        Severity = Severity.Info,
        UserSeverity = Severity.Info,
        Category = FindingCategory.Maintainability,
        Description = "The same 8 or more lines of logic appear in 2 places.",
        UserDescription = "The same lines appear twice.",
        FilePath = "dist/main/index.cjs",
        Line = 613,
    };

    /// <summary>
    /// The JSON said the vulnerability data was 739,876 days old, which is the age of
    /// <see cref="DateTimeOffset.MinValue"/>. The date beside it was already nulled; the age
    /// measured from it was not.
    /// </summary>
    [Fact]
    public void Data_that_was_never_looked_up_has_no_age()
    {
        using var document = JsonDocument.Parse(
            JsonReportWriter.Write(Report(VulnerabilityDataProvenance.Unavailable)));

        var data = document.RootElement.GetProperty("vulnerabilityData");

        Assert.Equal("None", data.GetProperty("origin").GetString());
        Assert.False(data.TryGetProperty("asOf", out _));
        Assert.False(data.TryGetProperty("ageInDays", out _));
    }

    [Fact]
    public void Data_that_was_looked_up_still_reports_its_age()
    {
        var live = new VulnerabilityDataProvenance
        {
            Origin = VulnerabilityDataOrigin.Live,
            AsOf = DateTimeOffset.Now.AddDays(-2),
            Source = "OSV.dev, queried live",
        };

        using var document = JsonDocument.Parse(JsonReportWriter.Write(Report(live)));

        Assert.Equal(
            2,
            document.RootElement.GetProperty("vulnerabilityData")
                .GetProperty("ageInDays").GetInt32());
    }

    /// <summary>
    /// The provenance phrase finishes "checked against ...", so dropping it into "Dependency
    /// checks used ..." produced "Dependency checks used no vulnerability data was available."
    /// </summary>
    [Fact]
    public void The_vulnerability_data_section_is_a_sentence()
    {
        var markdown = MarkdownReportWriter.Write(Report(VulnerabilityDataProvenance.Unavailable));

        Assert.DoesNotContain(
            "used no vulnerability data was available", markdown, StringComparison.Ordinal);

        Assert.Contains(
            "No vulnerability data was available", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// An informational finding is still a claim about a place in somebody's code. The list said
    /// a block of lines repeats and did not say where, while the JSON export carried the file
    /// and the line all along.
    /// </summary>
    [Fact]
    public void An_informational_finding_says_where_it_is()
    {
        var markdown = MarkdownReportWriter.Write(
            Report(VulnerabilityDataProvenance.Unavailable, Informational));

        Assert.Contains("### Informational (1)", markdown, StringComparison.Ordinal);
        Assert.Contains("dist/main/index.cjs:613", markdown, StringComparison.Ordinal);
    }
}
