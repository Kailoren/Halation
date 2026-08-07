using Halation.Core.Model;

namespace Halation.Tests;

/// <summary>
/// What a reader is told once they have said an application has a reason for something.
/// </summary>
/// <remarks>
/// The defect these were written for was live and contradicted itself in a single card: a
/// cleaner's author affirmed a reason to read browser cookies, and the report printed "You told
/// Halation this application has a reason to read your browser cookies" directly above
/// VC-MAL-002's remediation, which reads "Do not run this application." The remediation was
/// written for the case where nobody has a reason, and nothing rewrote it when the capability
/// split landed.
/// </remarks>
public class CapabilityGuidanceTests
{
    private static Finding Cookies(PurposeSource? explainedBy = null) => new()
    {
        RuleId = "VC-MAL-002",
        Title = "Application reads browser session cookies",
        Severity = Severity.Critical,
        UserSeverity = Severity.Critical,
        Category = FindingCategory.CodeSafety,
        Capability = Capability.BrowserCookies,
        Description = "Reads a browser cookie database.",
        UserDescription = "Reads your browser cookies.",
        Remediation = "Do not run this application.",
        UserRemediation = "Do not run this application.",
        ExplainedBy = explainedBy,
    };

    [Fact]
    public void An_unaccounted_capability_still_says_do_not_run_it()
    {
        // Nothing here softens the case the rule was written for. A cookie reader nobody has
        // vouched for is still a credential stealer as far as this report is concerned.
        var finding = Cookies();

        Assert.Equal(
            "Do not run this application.", finding.GuidanceFor(Audience.Developer));
    }

    [Fact]
    public void Accounting_for_it_replaces_the_advice_rather_than_removing_it()
    {
        var finding = Cookies(PurposeSource.Reader);
        var guidance = finding.GuidanceFor(Audience.Developer);

        Assert.NotNull(guidance);

        // The contradiction that prompted all this.
        Assert.DoesNotContain("Do not run", guidance, StringComparison.OrdinalIgnoreCase);

        // And it says something worth reading instead of merely going quiet, which is the whole
        // point: this tool is for helping people build better applications, and somebody who has
        // just confirmed they need a capability is at the one moment they will read about it.
        Assert.Equal(Capability.BrowserCookies.Safeguard(), guidance);
        Assert.Contains("read-only", guidance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Every_capability_has_advice_and_it_names_the_boundary()
    {
        // The generalisable half. Enumerating correct usage per verb per kind of application
        // does not converge; "having a reason to do this does not account for what you do with
        // the result" is one sentence per capability and covers the case that actually matters.
        foreach (var capability in Enum.GetValues<Capability>())
        {
            var safeguard = capability.Safeguard();

            Assert.False(string.IsNullOrWhiteSpace(safeguard), capability.ToString());
            Assert.Contains("accounts for", safeguard, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Advice_is_distinct_per_capability()
    {
        // A shared sentence would mean the fallback had quietly become the answer for everything.
        var written = Enum.GetValues<Capability>()
            .Select(c => c.Safeguard())
            .ToList();

        Assert.Equal(written.Count, written.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void A_finding_with_no_capability_is_untouched_by_any_of_this()
    {
        // The tier no declaration reaches. A leaked key carries no capability, so nothing here
        // can reach it however it was explained.
        var leaked = new Finding
        {
            RuleId = "VC-SEC-002",
            Title = "Live credential committed",
            Severity = Severity.Critical,
            UserSeverity = Severity.Info,
            Category = FindingCategory.Secrets,
            Description = "A live key.",
            UserDescription = "The author's key.",
            Remediation = "Revoke it.",
            UserRemediation = "Nothing for you to do.",
            ExplainedBy = PurposeSource.Reader,
        };

        Assert.Equal("Revoke it.", leaked.GuidanceFor(Audience.Developer));
    }
}
