using VibeCheck.Core;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;
using VibeCheck.Core.Rules;

namespace VibeCheck.Tests;

/// <summary>
/// What an application can do, as opposed to what it does wrong.
/// </summary>
/// <remarks>
/// Auto-updating and starting with Windows are how a great many correct programs work. Rated as
/// defects they charged a working application a band of score for having a feature, and one High
/// is enough to relabel it as having serious issues, which is how a scanner teaches people to
/// stop reading it. These tests hold the separation: reported in full, counted nowhere.
/// </remarks>
public class CapabilityTests : IDisposable
{
    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), $"vibecheck-capability-{Guid.NewGuid():N}");

    public CapabilityTests() => Directory.CreateDirectory(_scratch);

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    /// <summary>An updater, written the way updaters are written.</summary>
    private const string Updater = """
        var bytes = await new HttpClient().GetByteArrayAsync(url);
        var target = Path.Combine(Path.GetTempPath(), "update.exe");
        File.WriteAllBytes(target, bytes);
        Process.Start(target);
        """;

    private async Task<ScanReport> ScanAsync(string content, Audience audience = Audience.Developer)
    {
        File.WriteAllText(Path.Combine(_scratch, "Updater.cs"), content);

        return await new Scanner().ScanAsync(
            _scratch,
            ScanOptions.NoDependencyCheck with { Audience = audience });
    }

    /// <summary>
    /// The case this exists for. An application whose only remarkable property is that it
    /// updates itself is not an application with serious issues.
    /// </summary>
    [Fact]
    public async Task An_updater_does_not_cost_the_application_a_band()
    {
        var report = await ScanAsync(Updater);

        // Rated High, this fixture scored in the 40s and was labelled "serious issues" for
        // having an update routine. The top band is where an application whose only remarkable
        // property is that it updates itself belongs. It is not a perfect 100 because the same
        // fixture reads a remote response without a size limit, which is a real finding.
        Assert.Equal(ScoreBand.NoKnownIssues, report.Verdict.Band);
        Assert.True(report.Verdict.Score >= 90, $"scored {report.Verdict.Score}");

        Assert.DoesNotContain(report.Verdict.Explanation?.Describe() ?? [],
            line => line.Contains("High", StringComparison.Ordinal));
    }

    /// <summary>Reported in full, though. Not scoring it is not the same as hiding it.</summary>
    [Fact]
    public async Task It_is_still_reported()
    {
        var report = await ScanAsync(Updater);

        var capability = Assert.Single(report.Capabilities, c => c.RuleId == "VC-MAL-007");

        Assert.True(capability.IsCapability);
        Assert.NotEmpty(capability.Description);
        Assert.NotEmpty(capability.Location);
    }

    /// <summary>
    /// And kept out of the findings list, so nothing counting findings can count it by
    /// accident.
    /// </summary>
    [Fact]
    public async Task It_is_not_in_the_findings()
    {
        var report = await ScanAsync(Updater);

        Assert.DoesNotContain(report.Findings, f => f.IsCapability);
        Assert.DoesNotContain(report.Findings, f => f.RuleId == "VC-MAL-007");
        Assert.Equal(0, report.CountOf(Severity.Info));
    }

    /// <summary>Both reports carry it, in each one's own words.</summary>
    [Theory]
    [InlineData(Audience.Developer)]
    [InlineData(Audience.EndUser)]
    public async Task Both_readers_are_told(Audience audience)
    {
        var report = await ScanAsync(Updater, audience);

        Assert.NotEmpty(report.Capabilities);

        var markdown = MarkdownReportWriter.Write(report);

        Assert.Contains("What this application can do", markdown, StringComparison.Ordinal);
        Assert.Contains("does not affect the score", markdown.Replace("none of this affects", "does not affect"), StringComparison.Ordinal);
    }

    /// <summary>
    /// Switching reader must not lose them, since Rescore rebuilds the report around the other
    /// audience and a list left out of that rebuild would silently empty.
    /// </summary>
    [Fact]
    public async Task Switching_reader_keeps_them()
    {
        var report = await ScanAsync(Updater);
        var switched = Scanner.Rescore(report, Audience.EndUser);

        Assert.Equal(report.Capabilities.Count, switched.Capabilities.Count);
    }

    /// <summary>
    /// The unambiguous version of the same shape is still a finding, and still blocks. Moving
    /// the updater out must not take the dropper with it.
    /// </summary>
    [Fact]
    public void The_blocking_form_of_the_same_shape_is_untouched()
    {
        var rule = Assert.Single(
            new RuleEngine().Rules.OfType<PatternRule>(), r => r.Id == "VC-MAL-008");

        Assert.False(rule.IsCapability);
        Assert.True(rule.IsBlocking);
        Assert.Equal(Severity.Critical, rule.Severity);
    }

    /// <summary>
    /// Every capability rule must be weightless on both ladders. The section keeps them out of
    /// the arithmetic; this is the second lock, so a rule that escaped the section could still
    /// not move a number.
    /// </summary>
    [Fact]
    public void Capability_rules_carry_no_weight_on_either_ladder()
    {
        var capabilities = new RuleEngine().Rules
            .OfType<PatternRule>()
            .Where(r => r.IsCapability)
            .ToList();

        Assert.NotEmpty(capabilities);

        foreach (var rule in capabilities)
        {
            Assert.Equal(Severity.Info, rule.Severity);
            Assert.Equal(Severity.Info, rule.UserSeverity);
            Assert.False(rule.IsBlocking);
        }
    }
}
