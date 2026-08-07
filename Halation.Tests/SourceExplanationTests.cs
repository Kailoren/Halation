using Halation.Core.DeepPass;
using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Tests;

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
    /// <summary>
    /// A file whose comments really do say why, since a quote is now checked against them.
    /// </summary>
    private static TriagedFile File() => new()
    {
        File = new RecoveredFile
        {
            RelativePath = "src/Cleaner.cs",
            Content = """
                      // Clears stale sessions left by the browser.
                      // Registered at startup so the sweep runs before anything else opens.
                      public void Clear() { }
                      """,
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
    public void A_reason_that_is_not_in_the_file_is_dropped()
    {
        // The defect this was written for, and it was live. qwen2.5-coder:7b over FleetFinder's
        // source returned three explanations and none of them appeared anywhere in the source.
        // One claimed a reason for reading browser cookies in an application whose source does
        // not contain the word "cookie". Shown as "The code says why", that is the scanner
        // writing a note and signing the author's name to it.
        var answer = DeepPassPrompt.Parse(
            """
            {"findings":[],
             "explains":[{"capability":"BrowserCookies",
                          "reason":"The code reads HTTP responses from untrusted sources without validating them."}]}
            """,
            File());

        Assert.Empty(answer.Explains);
    }

    [Fact]
    public void A_quote_wrapped_across_comment_lines_still_matches()
    {
        // Whitespace and the comment markers themselves are normalised away, because a quote
        // spanning two wrapped lines arrives flattened. That is formatting, not a different
        // sentence, and dropping it would make the check useless on real code.
        var answer = DeepPassPrompt.Parse(
            """
            {"findings":[],
             "explains":[{"capability":"StartsWithWindows",
                          "reason":"Registered at startup so the sweep runs before anything else opens."}]}
            """,
            File());

        Assert.Single(answer.Explains);
        Assert.True(answer.Explains.ContainsKey(Capability.StartsWithWindows));
    }

    [Fact]
    public void A_fragment_too_short_to_mean_anything_is_dropped()
    {
        // Three words appear in almost any file by accident, which would let a fabricated
        // reason through on a coincidence rather than on evidence.
        var answer = DeepPassPrompt.Parse(
            """
            {"findings":[],"explains":[{"capability":"BrowserCookies","reason":"Clears"}]}
            """,
            File());

        Assert.Empty(answer.Explains);
    }

    [Fact]
    public void Both_halves_are_read_independently()
    {
        // A model that fumbles one should not cost the other. Returning early on a missing
        // findings array used to throw away anything that arrived beside it.
        var answer = DeepPassPrompt.Parse(
            """
            {"explains":[{"capability":"StartsWithWindows",
                          "reason":"Registered at startup so the sweep runs before anything else opens."}]}
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
             "explains":[{"capability":"ReadsYourMind",
                          "reason":"Clears stale sessions left by the browser."},
                         {"capability":"BrowserCookies",
                          "reason":"Clears stale sessions left by the browser."}]}
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
