using System.Text;
using System.Text.Json;

using Halation.Core.DeepPass;
using Halation.Core.Rules;

namespace Halation.Tests;

/// <summary>
/// The text the deep pass produces, on its way from the agent to the report.
/// </summary>
/// <remarks>
/// Both defects here were live for as long as the deep pass has existed and neither showed up
/// in any test, because both need text the fixtures never had: a character outside ASCII, and
/// an explanation longer than a label. They landed in the part of the report that exists
/// precisely because a pattern match could not say this much.
/// </remarks>
public class DeepPassTextTests
{
    /// <summary>
    /// UTF-8 on every stream to and from the agent.
    /// </summary>
    /// <remarks>
    /// Left unset, the pipes are decoded with the console code page, which on a British or
    /// American Windows install is Windows-1252. The agent emits UTF-8, so an em dash in a
    /// finding reached the interface as <c>â€"</c>. Asserted on the description rather than by
    /// running the agent, because the failure is invisible until the text happens to contain a
    /// character outside ASCII.
    /// </remarks>
    [Fact]
    public void Every_stream_to_the_agent_is_utf8()
    {
        var startInfo = ClaudeCodeCliBackend.BuildStartInfo(
            new ClaudeCodeCli { Path = @"C:\claude\claude.exe", Source = ClaudeCodeCliSource.Path },
            Path.GetTempPath());

        Assert.Equal(Encoding.UTF8.CodePage, startInfo.StandardOutputEncoding?.CodePage);
        Assert.Equal(Encoding.UTF8.CodePage, startInfo.StandardErrorEncoding?.CodePage);
        Assert.Equal(Encoding.UTF8.CodePage, startInfo.StandardInputEncoding?.CodePage);
    }

    /// <summary>
    /// And no byte order mark on the way in, because the input is a JSON document and a mark is
    /// three bytes the parser at the other end is not expecting.
    /// </summary>
    [Fact]
    public void Nothing_writes_a_byte_order_mark_to_the_agent()
    {
        var startInfo = ClaudeCodeCliBackend.BuildStartInfo(
            new ClaudeCodeCli { Path = @"C:\claude\claude.exe", Source = ClaudeCodeCliSource.Path },
            Path.GetTempPath());

        Assert.Empty(startInfo.StandardInputEncoding!.GetPreamble());
    }

    /// <summary>
    /// A round trip through the encoding the pipes now use, so the em dash that started this is
    /// covered by name rather than by inference.
    /// </summary>
    [Theory]
    [InlineData("binding NavigateUri to attacker-influenced data — is in the consuming app")]
    [InlineData("the caller passes “user input” straight through")]
    [InlineData("a path ending in … and a bullet •")]
    public void Text_outside_ascii_survives_the_pipe(string original)
    {
        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        Assert.Equal(original, encoding.GetString(encoding.GetBytes(original)));

        // And the shape the bug produced is not what comes back.
        Assert.DoesNotContain("â€", encoding.GetString(encoding.GetBytes(original)),
            StringComparison.Ordinal);
    }

    // ---- Length --------------------------------------------------------------

    /// <summary>
    /// The reader is meant to finish these sentences. At 400 characters every one of them
    /// stopped mid-word, in the end user's view where the explanation is the entire content.
    /// </summary>
    [Fact]
    public void An_explanation_is_not_cut_off_mid_sentence()
    {
        var impact = string.Join(" ", Enumerable.Repeat("the update server sends back a link", 40));

        Assert.True(impact.Length > 400, "fixture must exceed the old cap to be a test at all");

        var finding = Assert.Single(DeepPassPrompt.Parse(Json(impact), Triaged()).Findings);

        Assert.DoesNotContain("…", finding.UserDescription, StringComparison.Ordinal);
        Assert.Contains(impact, finding.UserDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// Still bounded, though. This text comes back from a model that has just read a file the
    /// scanner assumes is hostile, so a runaway answer must not become a runaway report.
    /// </summary>
    [Fact]
    public void But_it_is_still_bounded()
    {
        var runaway = new string('x', Redaction.MaxProse * 3);

        var finding = Assert.Single(DeepPassPrompt.Parse(Json(runaway), Triaged()).Findings);

        Assert.True(
            finding.UserDescription.Length <= Redaction.MaxProse + 1,
            $"ran to {finding.UserDescription.Length}");

        Assert.EndsWith("…", finding.UserDescription, StringComparison.Ordinal);
    }

    private static string Json(string userImpact) => JsonSerializer.Serialize(new
        {
            findings = new[]
            {
                new
                {
                    title = "Update URL is stored unvalidated",
                    severity = "high",
                    user_severity = "high",
                    confidence = "high",
                    why_rules_miss_it = "the guard is in another file",
                    reachability = "reachable from the update check",
                    user_impact = userImpact,
                    evidence = "var url = response.UpdateUrl;",
                    remediation = "validate the scheme before opening it",
                    file = "src/MainViewModel.cs",
                },
            },
        });

    private static TriagedFile Triaged() => new()
    {
        File = new Core.Recovery.RecoveredFile
        {
            RelativePath = "src/MainViewModel.cs",
            Content = "var url = response.UpdateUrl;",
            Language = Core.Recovery.SourceLanguage.CSharp,
        },
        Reason = "test",
    };
}
