using System.Text.Json;

using Halation.Core.DeepPass;
using Halation.Core.Dependencies;
using Halation.Core.Model;
using Halation.Core.Reporting;
using Halation.Core.Scoring;

namespace Halation.Tests;

/// <summary>
/// What the exported report says about the machine, which is what makes a local model report
/// worth reading. Nothing here is transmitted; it is written into a file the reader chooses to
/// share, so the tests care about what is present and what is deliberately absent.
/// </summary>
public sealed class ScanEnvironmentTests
{
    [Fact]
    public void Describe_FillsWhatAPlatformNeutralAssemblyCanKnow()
    {
        var machine = ScanEnvironment.Describe();

        Assert.False(string.IsNullOrWhiteSpace(machine.OperatingSystem));
        Assert.False(string.IsNullOrWhiteSpace(machine.Architecture));
        Assert.True(machine.ProcessorCount > 0);
    }

    /// <summary>
    /// The section is for a model that ran here. On the Claude routes the reader's graphics card
    /// has nothing to do with the result, so printing it would be collecting for its own sake.
    /// </summary>
    [Fact]
    public void TheMarkdownSection_IsAbsentWhenNothingRanLocally()
    {
        var markdown = MarkdownReportWriter.Write(Report(null));

        Assert.DoesNotContain("## This machine", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMarkdownSection_NamesTheCardTheModelAndTheRuntime()
    {
        var markdown = MarkdownReportWriter.Write(Report(new ScanEnvironment
        {
            GraphicsAdapter = "NVIDIA GeForce RTX 4060",
            GraphicsMemoryBytes = 8L * 1024 * 1024 * 1024,
            SystemMemoryBytes = 32L * 1024 * 1024 * 1024,
            DeepPassModel = "qwen2.5-coder:7b",
            DeepPassRuntime = "Ollama",
            DeepPassRanLocally = true,
        }));

        Assert.Contains("## This machine", markdown, StringComparison.Ordinal);
        Assert.Contains("NVIDIA GeForce RTX 4060", markdown, StringComparison.Ordinal);
        Assert.Contains("8 GB", markdown, StringComparison.Ordinal);
        Assert.Contains("qwen2.5-coder:7b", markdown, StringComparison.Ordinal);
        Assert.Contains("Ollama", markdown, StringComparison.Ordinal);

        // The reader is told what is in the file before they are asked to share it.
        Assert.Contains("Nothing here was sent anywhere", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// Zero means "could not be read", never "this machine has no memory", so the key is dropped
    /// rather than emitted as a measurement that would be false.
    /// </summary>
    [Fact]
    public void UnreadableFigures_AreAbsentFromTheJsonRatherThanZero()
    {
        var json = JsonReportWriter.Write(Report(new ScanEnvironment
        {
            ProcessorCount = 8,
            DeepPassRanLocally = true,
        }));

        using var document = JsonDocument.Parse(json);
        var machine = document.RootElement.GetProperty("environment");

        Assert.False(machine.TryGetProperty("graphicsMemoryBytes", out _));
        Assert.False(machine.TryGetProperty("systemMemoryBytes", out _));
        Assert.Equal(8, machine.GetProperty("processors").GetInt32());
    }

    [Fact]
    public void TheJson_OmitsTheSectionEntirelyWhenNoneWasGathered()
    {
        using var document = JsonDocument.Parse(JsonReportWriter.Write(Report(null)));

        Assert.False(document.RootElement.TryGetProperty("environment", out _));
    }

    /// <summary>
    /// Named by port, so a runtime that has since been closed is still named in the record of a
    /// scan it answered.
    /// </summary>
    [Theory]
    [InlineData("http://localhost:11434/v1/chat/completions", "Ollama")]
    [InlineData("http://127.0.0.1:1234/v1/chat/completions", "LM Studio")]
    [InlineData("http://localhost:9999/v1/chat/completions", null)]
    public void ALocalRuntime_IsNamedByThePortItListensOn(string url, string? expected) =>
        Assert.Equal(expected, LocalRuntimeProbe.NameFor(new Uri(url)));

    // ---- The sharing copy --------------------------------------------------

    /// <summary>
    /// The whole point: a reader helping with a local model test must not have to publish their
    /// own source to do it.
    /// </summary>
    [Fact]
    public void TheSharingCopy_CarriesNoCodeNoPathsAndNoHash()
    {
        var shared = WithFindings().ForSharing();
        var markdown = MarkdownReportWriter.Write(shared);
        var json = JsonReportWriter.Write(shared);

        foreach (var text in new[] { markdown, json })
        {
            Assert.DoesNotContain("var password = \"hunter2\";", text, StringComparison.Ordinal);
            Assert.DoesNotContain("src/Secrets/Vault.cs", text, StringComparison.Ordinal);
            Assert.DoesNotContain("CustomerPortal.exe", text, StringComparison.Ordinal);
            Assert.DoesNotContain(new string('a', 64), text, StringComparison.Ordinal);
        }
    }

    /// <summary>The findings themselves survive: this is a redaction, not a summary.</summary>
    [Fact]
    public void TheSharingCopy_KeepsTheFindingsAndTheirRatings()
    {
        var shared = WithFindings().ForSharing();

        var finding = Assert.Single(shared.Findings);

        Assert.Equal("Hardcoded credential", finding.Title);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Null(finding.Evidence);
        Assert.Null(finding.Line);
    }

    /// <summary>
    /// Paths become stable labels rather than vanishing, so "all of them in one file" still reads
    /// as that, and the extension stays because the language changes what the checks could do.
    /// </summary>
    [Fact]
    public void TheSharingCopy_GroupsByFileWithoutNamingIt()
    {
        var report = WithFindings(
            Finding("src/A.cs", "one"),
            Finding("src/A.cs", "two"),
            Finding("src/B.cs", "three"));

        var paths = report.ForSharing().Findings.Select(f => f.FilePath).ToArray();

        Assert.Equal(paths[0], paths[1]);
        Assert.NotEqual(paths[1], paths[2]);
        Assert.All(paths, p => Assert.Contains("(.cs)", p, StringComparison.Ordinal));
        Assert.All(paths, p => Assert.DoesNotContain("src", p, StringComparison.Ordinal));
    }

    /// <summary>
    /// A redacted report that does not announce itself lets somebody read absent findings as
    /// findings that were not there.
    /// </summary>
    [Fact]
    public void TheSharingCopy_SaysThatItIsOne()
    {
        Assert.Contains("This is the sharing copy",
            MarkdownReportWriter.Write(WithFindings().ForSharing()), StringComparison.Ordinal);

        using var document = JsonDocument.Parse(JsonReportWriter.Write(WithFindings().ForSharing()));
        Assert.True(document.RootElement.GetProperty("shared").GetBoolean());
    }

    [Fact]
    public void TheOrdinaryCopy_IsUntouched()
    {
        var markdown = MarkdownReportWriter.Write(WithFindings());

        Assert.Contains("var password = \"hunter2\";", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("This is the sharing copy", markdown, StringComparison.Ordinal);
    }

    private static Finding Finding(string path, string title) => new()
    {
        RuleId = "VC-SEC-001",
        Title = title,
        Severity = Severity.Critical,
        UserSeverity = Severity.Low,
        Category = FindingCategory.Secrets,
        Description = "d",
        UserDescription = "u",
        FilePath = path,
        Line = 12,
        Evidence = "var password = \"hunter2\";",
    };

    private static ScanReport WithFindings(params Finding[] findings)
    {
        var list = findings.Length > 0
            ? findings
            : [Finding("src/Secrets/Vault.cs", "Hardcoded credential")];

        return Report(null) with
        {
            ArtifactName = "CustomerPortal.exe",
            Sha256 = new string('a', 64),
            Findings = list,
            Verdict = ScoreCalculator.Calculate(list),
        };
    }

    private static ScanReport Report(ScanEnvironment? machine) => new()
    {
        ArtifactName = "fixture",
        Kind = ArtifactKind.SourceTree,
        ArtifactBytes = 1,
        Sha256 = new string('0', 64),
        ScannedAt = DateTimeOffset.UnixEpoch,
        Verdict = ScoreCalculator.Calculate([]),
        Coverage = new CoverageReport { Percent = 100, Basis = "fixture" },
        Findings = [],
        CategoryScores = ScoreCalculator.CategoryScores([]),
        VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
        Effort = new ScanEffort
        {
            RecoveryMethod = "fixture",
            FilesRecovered = 1,
            BytesRecovered = 1,
            ChecksRun = 40,
            FilesChecked = 1,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = VulnerabilityDataProvenance.Unavailable,
        },
        ScannerVersion = "test",
        Environment = machine,
    };
}
