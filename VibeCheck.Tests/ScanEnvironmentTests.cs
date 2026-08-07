using System.Text.Json;

using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Tests;

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
