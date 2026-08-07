using Halation.Core.Model;

namespace Halation.Tests;

/// <summary>
/// The declared kind of application, which frames the capability questions and decides nothing.
/// </summary>
/// <remarks>
/// These tests exist because the failure mode is silent and one-directional: a label that
/// quietly accounted for a capability would produce a quieter report that looks identical to an
/// application which genuinely had nothing to report.
/// </remarks>
public class ApplicationKindTests
{
    [Fact]
    public void Nothing_is_stated_by_default_and_that_is_not_the_same_as_general()
    {
        // A missing answer must never read as a benign one, exactly as a missing audience file
        // means "not asked yet" rather than a silent default.
        Assert.Equal(0, (int)ApplicationKind.Unstated);
        Assert.NotEqual(ApplicationKind.Unstated, ApplicationKind.General);
        Assert.Empty(ApplicationKind.Unstated.Expects());
    }

    [Fact]
    public void Answering_general_expects_nothing()
    {
        // The point Ali made: declaring an application general means an observed cookie read is
        // a real issue, not an excused one.
        Assert.Empty(ApplicationKind.General.Expects());
        Assert.False(ApplicationKind.General.Expects(Capability.BrowserCookies));
    }

    [Fact]
    public void A_security_tool_gets_no_blanket_expectation()
    {
        // Ali's call, 2026-08-06. It is the most flattering label available and would otherwise
        // reach cookies, saved passwords and wallet files at once, so it earns none of them and
        // each is asked individually instead.
        Assert.Empty(ApplicationKind.SecurityTool.Expects());

        foreach (var capability in Enum.GetValues<Capability>())
        {
            Assert.False(ApplicationKind.SecurityTool.Expects(capability), capability.ToString());
        }
    }

    [Fact]
    public void The_kinds_that_do_expect_something_expect_only_their_own()
    {
        Assert.True(ApplicationKind.CleanerOrPrivacy.Expects(Capability.BrowserCookies));
        Assert.False(ApplicationKind.CleanerOrPrivacy.Expects(Capability.BrowserCredentials));
        Assert.False(ApplicationKind.CleanerOrPrivacy.Expects(Capability.CryptocurrencyWallets));

        Assert.True(ApplicationKind.PasswordManager.Expects(Capability.BrowserCredentials));
        Assert.False(ApplicationKind.PasswordManager.Expects(Capability.BrowserCookies));

        Assert.True(ApplicationKind.CryptoWallet.Expects(Capability.ClipboardMonitoring));
        Assert.False(ApplicationKind.CryptoWallet.Expects(Capability.ChatTokens));
    }

    /// <summary>
    /// The guarantee the whole feature rests on: no kind reaches the tier that no purpose is
    /// allowed to reach.
    /// </summary>
    [Fact]
    public void No_kind_expects_every_capability()
    {
        var all = Enum.GetValues<Capability>().Length;

        foreach (var kind in Enum.GetValues<ApplicationKind>())
        {
            Assert.True(kind.Expects().Count < all, kind.ToString());
        }
    }

    [Fact]
    public void Every_capability_is_still_asked_about_whatever_the_kind()
    {
        // Softening the wording is the only thing a kind may do. If it ever stopped producing a
        // question, it would have become a suppression mechanism.
        foreach (var kind in Enum.GetValues<ApplicationKind>())
        {
            foreach (var capability in Enum.GetValues<Capability>())
            {
                var question = kind.Question(capability);

                Assert.EndsWith("reason to?", question, StringComparison.Ordinal);
                Assert.Contains(
                    capability.Humanise()[1..], question, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void The_wording_says_whether_this_is_normal_for_what_was_declared()
    {
        var expected = ApplicationKind.CleanerOrPrivacy.Question(Capability.BrowserCookies);
        var surprising = ApplicationKind.General.Question(Capability.BrowserCookies);

        Assert.Contains("is normal for", expected, StringComparison.Ordinal);
        Assert.Contains("is not usual for", surprising, StringComparison.Ordinal);

        // The surprising case names what would normally have it, which is what makes the worry
        // checkable rather than vague.
        Assert.Contains("a cleaner or a privacy tool", surprising, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_kind_has_a_name_of_its_own()
    {
        var names = Enum.GetValues<ApplicationKind>().Select(k => k.Humanise()).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain(names, n => string.IsNullOrWhiteSpace(n));
    }
}
