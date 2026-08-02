using VibeCheck.Core;
using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

/// <summary>
/// The deep pass costs the reader money and sends their code to a third party, so its
/// guarantees are the tested part: it never runs unasked, never runs on an isolated scan,
/// and its findings can never make the strongest claim in the report.
/// </summary>
public class DeepPassTests
{
    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    private static Finding FindingIn(string path) => new()
    {
        RuleId = "VC-TEST-001",
        Title = "test finding",
        Severity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description = "x",
        FilePath = path,
    };

    // ---- The guarantees ----------------------------------------------------

    [Fact]
    public void Is_off_when_no_key_is_supplied() =>
        Assert.False(new ScanOptions().DeepPassEnabled);

    /// <summary>
    /// Isolate mode promises no network access at all. A stored key must not quietly
    /// override that promise.
    /// </summary>
    [Fact]
    public void Is_off_in_isolate_mode_even_with_a_key() =>
        Assert.False(new ScanOptions { Isolate = true, DeepPassApiKey = "sk-ant-test" }.DeepPassEnabled);

    [Fact]
    public void Is_on_only_with_a_key_and_no_isolation() =>
        Assert.True(new ScanOptions { DeepPassApiKey = "sk-ant-test" }.DeepPassEnabled);

    [Fact]
    public async Task Produces_nothing_when_disabled()
    {
        var result = await DeepPassRunner.RunAsync(
            [File("a.cs", "class A { }")], [], new ScanOptions());

        Assert.Empty(result.Findings);
        Assert.Empty(result.Limitations);
    }

    // ---- Triage ------------------------------------------------------------

    /// <summary>
    /// The whole point of surface-based triage. Both findings a hand audit caught and the
    /// pattern pass missed were in files with zero findings; selecting only flagged regions
    /// would never have shown the model either file.
    /// </summary>
    [Fact]
    public void Selects_a_file_that_handles_untrusted_input_with_no_findings()
    {
        var selected = DeepPassTriage.Select(
            [
                File("Client.cs", "var json = await Http.GetStringAsync(url);"),
                File("Maths.cs", "int Add(int a, int b) => a + b;"),
            ],
            findings: []);

        Assert.Contains(selected, s => s.File.RelativePath == "Client.cs");
        Assert.DoesNotContain(selected, s => s.File.RelativePath == "Maths.cs");
    }

    /// <summary>
    /// The caller hop. Reading a flagged line alone under-grades reachability: a real
    /// unbounded stackalloc was recorded as local-only until its caller showed it was fed
    /// from an HTTP response.
    /// </summary>
    [Fact]
    public void Selects_files_that_call_into_a_flagged_file()
    {
        var selected = DeepPassTriage.Select(
            [
                File("ShipLockerReader.cs", "static string Normalize(string s) { }"),
                File("EdsmCoordinateSource.cs", "var k = ShipLockerReader.Normalize(name);"),
            ],
            findings: [FindingIn("ShipLockerReader.cs")]);

        Assert.Contains(selected, s => s.File.RelativePath == "EdsmCoordinateSource.cs"
                                       && s.Reason.Contains("calls into", StringComparison.Ordinal));
    }

    /// <summary>Flagged files carry their findings, so the model judges rather than rediscovers.</summary>
    [Fact]
    public void Passes_known_findings_along_with_the_flagged_file()
    {
        var selected = DeepPassTriage.Select(
            [File("Client.cs", "var json = await Http.GetStringAsync(url);")],
            findings: [FindingIn("Client.cs")]);

        var file = Assert.Single(selected);
        Assert.Single(file.KnownFindings);
        Assert.Contains("rule matched", file.Reason, StringComparison.Ordinal);
    }

    /// <summary>Flagged files first: if the budget runs out, it runs out on the weakest candidates.</summary>
    [Fact]
    public void Orders_flagged_files_ahead_of_the_wider_surface()
    {
        var selected = DeepPassTriage.Select(
            [
                File("Plain.cs", "var a = await Http.GetStringAsync(url);"),
                File("Flagged.cs", "var b = await Http.GetStringAsync(url);"),
            ],
            findings: [FindingIn("Flagged.cs")]);

        Assert.Equal("Flagged.cs", selected[0].File.RelativePath);
    }

    /// <summary>The key holder pays per file, so the ceiling has to hold.</summary>
    [Fact]
    public void Respects_the_file_ceiling()
    {
        var files = Enumerable.Range(0, 100)
            .Select(i => File($"File{i}.cs", "await Http.GetStringAsync(url);"))
            .ToList();

        Assert.Equal(5, DeepPassTriage.Select(files, [], maxFiles: 5).Count);
    }

    [Fact]
    public void Truncates_a_file_too_large_to_send_rather_than_dropping_it()
    {
        var excerpt = DeepPassTriage.Excerpt(File("Big.cs", new string('x', 200_000)));

        Assert.True(excerpt.Length < 200_000);
        Assert.Contains("truncated", excerpt, StringComparison.Ordinal);
    }

    // ---- Cost --------------------------------------------------------------

    [Fact]
    public void Estimates_cost_at_the_published_rates()
    {
        var result = new DeepPassResult
        {
            Usage = new TokenUsage { Input = 1_000_000, Output = 1_000_000 },
        };

        Assert.Equal(30.00m, result.EstimatedCost);
    }

    /// <summary>
    /// The system prompt is cached on every request, so cached tokens are most of what the
    /// pass reads. Pricing them at zero reported a small fraction of the real bill.
    /// </summary>
    [Fact]
    public void Prices_cached_tokens_rather_than_ignoring_them()
    {
        var usage = new TokenUsage { CacheWrite = 1_000_000, CacheRead = 1_000_000 };

        Assert.Equal(6.75m, usage.EstimatedCost);
    }

    /// <summary>
    /// <c>input_tokens</c> excludes anything the cache served, so it is not the size of the
    /// prompt. Reporting it as one would understate what was sent.
    /// </summary>
    [Fact]
    public void Counts_cached_tokens_as_input_that_was_sent()
    {
        var usage = new TokenUsage { Input = 100, CacheWrite = 20, CacheRead = 3_000 };

        Assert.Equal(3_120, usage.TotalInput);
    }

    [Fact]
    public void Adds_usage_across_the_files_it_reviewed()
    {
        var total = new TokenUsage { Input = 1, Output = 2, CacheWrite = 3, CacheRead = 4 }
                    + new TokenUsage { Input = 10, Output = 20, CacheWrite = 30, CacheRead = 40 };

        Assert.Equal(11, total.Input);
        Assert.Equal(22, total.Output);
        Assert.Equal(33, total.CacheWrite);
        Assert.Equal(44, total.CacheRead);
    }
}
