using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

/// <summary>
/// The author's own stated reason, read out of the source by the deep pass.
/// </summary>
/// <remarks>
/// It exists so somebody who already wrote down why their code reads cookies is asked to confirm
/// their own note rather than retype it. It must never become an answer: the text arrived inside
/// the artifact under examination.
/// </remarks>
public class SourceExplanationTests
{
    private static TriagedFile File() => new()
    {
        File = new RecoveredFile
        {
            RelativePath = "src/Cleaner.cs",
            Content = "// Clears stale sessions.",
            Language = SourceLanguage.CSharp,
        },
        Reason = "handles untrusted input",
    };

    [Fact]
    public void A_stated_reason_is_read_back_against_its_capability()
    {
        var answer = DeepPassPrompt.Parse(
            """
            {"findings":[],
             "explains":[{"capability":"BrowserCookies",
                          "reason":"Clears stale sessions left by the browser."}]}
            """,
            File());

        Assert.Equal(
            "Clears stale sessions left by the browser.",
            answer.Explains[Capability.BrowserCookies]);
    }

    [Fact]
    public void Both_halves_are_read_independently()
    {
        // A model that fumbles one should not cost the other. Returning early on a missing
        // findings array used to throw away anything that arrived beside it.
        var answer = DeepPassPrompt.Parse(
            """
            {"explains":[{"capability":"StartsWithWindows","reason":"Runs the sync agent."}]}
            """,
            File());

        Assert.Empty(answer.Findings);
        Assert.Single(answer.Explains);
    }

    [Fact]
    public void A_capability_the_model_invented_is_dropped()
    {
        // This text is put in front of a reader as something their application said about
        // itself, so only the seven named powers are accepted.
        var answer = DeepPassPrompt.Parse(
            """
            {"findings":[],
             "explains":[{"capability":"ReadsYourMind","reason":"Trust me."},
                         {"capability":"BrowserCookies","reason":"Real one."}]}
            """,
            File());

        Assert.Single(answer.Explains);
        Assert.True(answer.Explains.ContainsKey(Capability.BrowserCookies));
    }

    [Fact]
    public void An_empty_answer_is_the_normal_one()
    {
        // Expected for decompiled code, where the comments no longer exist.
        var answer = DeepPassPrompt.Parse("""{"findings":[],"explains":[]}""", File());

        Assert.Empty(answer.Explains);
    }

    [Fact]
    public void The_schema_asks_for_it_and_requires_it()
    {
        // Strict structured output rejects a schema whose declared properties are not all
        // required, so leaving it off "required" would fail every request rather than simply
        // making the field optional.
        var required = DeepPassPrompt.FindingSchema["required"].EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        Assert.Contains("findings", required);
        Assert.Contains("explains", required);

        Assert.Contains(
            "explains", DeepPassPrompt.SystemPrompt, StringComparison.Ordinal);
    }

    [Fact]
    public void What_the_source_says_never_settles_the_question()
    {
        // The guarantee. Everything above is a prefill; only the reader accounts for anything.
        Assert.False(PurposeSource.SourceComment.CanAccount());
    }
}
