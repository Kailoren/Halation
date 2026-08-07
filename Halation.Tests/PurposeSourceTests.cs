using Halation.Core.Model;

namespace Halation.Tests;

/// <summary>
/// Who is allowed to settle a capability question, as opposed to merely raise it.
/// </summary>
public class PurposeSourceTests
{
    private static Finding Cookies() => new()
    {
        RuleId = "VC-MAL-002",
        Title = "Reads browser session cookies",
        Severity = Severity.Critical,
        UserSeverity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        Capability = Capability.BrowserCookies,
        Description = "Reads a cookie database.",
        UserDescription = "Reads your cookies.",
    };

    [Fact]
    public void Only_the_reader_can_account_for_anything()
    {
        Assert.True(PurposeSource.Reader.CanAccount());
        Assert.False(PurposeSource.Manifest.CanAccount());
        Assert.False(PurposeSource.SourceComment.CanAccount());
    }

    [Fact]
    public void A_claim_from_inside_the_artifact_raises_the_question_and_does_not_answer_it()
    {
        // The rule was documented on PurposeSource.Manifest from the start and enforced nowhere:
        // PurposeSplit asked only whether the capability was in the set. Nothing constructed a
        // non-reader purpose, so it was latent. Adding SourceComment is exactly how a latent
        // hole becomes a live one.
        var claimed = new DeclaredPurpose
        {
            Accounted = new HashSet<Capability> { Capability.BrowserCookies },
            Source = PurposeSource.SourceComment,
        };

        // It says something...
        Assert.True(claimed.Claims(Capability.BrowserCookies));

        // ...and it settles nothing.
        Assert.False(claimed.Accounts(Capability.BrowserCookies));

        var (findings, capabilities) = PurposeSplit.Apply([Cookies()], claimed);

        Assert.Single(findings);
        Assert.Empty(capabilities);
    }

    [Fact]
    public void The_reader_saying_so_does_take_it_out_of_the_arithmetic()
    {
        var affirmed = DeclaredPurpose.FromReader(Capability.BrowserCookies);

        var (findings, capabilities) = PurposeSplit.Apply([Cookies()], affirmed);

        Assert.Empty(findings);
        var moved = Assert.Single(capabilities);
        Assert.Equal(PurposeSource.Reader, moved.ExplainedBy);
    }

    [Fact]
    public void Each_source_says_plainly_what_it_is_worth()
    {
        var reader = DeclaredPurpose.FromReader(Capability.BrowserCookies);

        var comment = new DeclaredPurpose
        {
            Accounted = new HashSet<Capability> { Capability.BrowserCookies },
            Source = PurposeSource.SourceComment,
        };

        Assert.StartsWith("You told VibeCheck", reader.Attribution(Capability.BrowserCookies),
            StringComparison.Ordinal);

        // The untrusted ones have to disclaim themselves in the sentence a reader actually sees,
        // not only in a doc comment nobody reads.
        Assert.Contains("not confirmation",
            new DeclaredPurpose
            {
                Accounted = new HashSet<Capability> { Capability.BrowserCookies },
                Source = PurposeSource.Manifest,
            }.Attribution(Capability.BrowserCookies),
            StringComparison.Ordinal);

        Assert.Contains("without vouching for it",
            comment.Attribution(Capability.BrowserCookies), StringComparison.Ordinal);
    }
}
