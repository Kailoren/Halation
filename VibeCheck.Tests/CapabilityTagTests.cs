using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;

namespace VibeCheck.Tests;

/// <summary>
/// Which findings name a power a declared purpose could account for, and which sit outside
/// anything a declaration can reach.
/// </summary>
/// <remarks>
/// Reading a browser's cookie database is what credential-stealing malware does and what a
/// cleaning utility does. Rated on the observation alone the scanner tells the author of a
/// cleaner not to install their own work, and a reader who meets that once stops believing the
/// banner. These tests hold the line the fix depends on: the powers an application might have
/// a reason for are named, and the techniques nothing has a reason for are not.
/// </remarks>
public class CapabilityTagTests
{
    private static readonly IReadOnlyList<PatternRule> Rules =
        [.. new RuleEngine().Rules.OfType<PatternRule>()];

    /// <summary>
    /// Rules that block and deliberately name no capability, so no declared purpose can reach
    /// them.
    /// </summary>
    /// <remarks>
    /// Written out rather than derived. A new blocking rule fails the test below until somebody
    /// decides which of the two it is, which is the whole point: the default must be a decision
    /// rather than an omission.
    /// </remarks>
    private static readonly string[] Absolute = ["VC-MAL-008"];

    [Fact]
    public void Every_blocking_rule_either_names_a_capability_or_is_declared_absolute()
    {
        var undecided = Rules
            .Where(r => r.IsBlocking && r.Capability is null)
            .Select(r => r.Id)
            .Except(Absolute, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            undecided.Count == 0,
            "These blocking rules name no capability and are not listed as absolute, so nothing "
            + "says whether a declared purpose may account for them: "
            + string.Join(", ", undecided));
    }

    /// <summary>
    /// The load-bearing half. Piping a web response into a shell has no legitimate purpose to
    /// declare, and if everything were taggable then declaring a purpose would be a bypass.
    /// </summary>
    [Fact]
    public void The_absolute_rules_really_carry_no_capability()
    {
        foreach (var id in Absolute)
        {
            var rule = Assert.Single(Rules, r => r.Id == id);

            Assert.True(rule.IsBlocking, $"{id} is listed as absolute but does not block.");
            Assert.Null(rule.Capability);
        }
    }

    /// <summary>
    /// A credential in the bundle is leaked whoever shipped it and whatever the application is
    /// for, so no secret rule may become explainable.
    /// </summary>
    [Fact]
    public void No_secret_rule_names_a_capability() =>
        Assert.All(
            Rules.Where(r => r.Category == FindingCategory.Secrets),
            rule => Assert.Null(rule.Capability));

    /// <summary>
    /// Most of the catalog describes things that are wrong regardless, and if that stopped being
    /// true the tag would have spread past what it was for.
    /// </summary>
    [Fact]
    public void The_untagged_rules_are_still_the_large_majority()
    {
        var tagged = Rules.Count(r => r.Capability is not null);

        Assert.True(
            tagged * 4 < Rules.Count,
            $"{tagged} of {Rules.Count} rules name a capability, which is more than this was "
            + "meant to cover.");
    }

    /// <summary>
    /// A rule already reported as a capability rather than a defect must say which one, or the
    /// report can list what an application can do without naming it.
    /// </summary>
    [Fact]
    public void Every_capability_rule_names_which_capability_it_is() =>
        Assert.All(
            Rules.Where(r => r.IsCapability),
            rule => Assert.NotNull(rule.Capability));

    /// <summary>
    /// Every value is claimed, so a value added without a rule behind it, or left behind by a
    /// deleted rule, does not sit in the taxonomy describing nothing.
    /// </summary>
    [Fact]
    public void Every_capability_has_a_rule_that_detects_it()
    {
        var detected = Rules.Select(r => r.Capability).OfType<Capability>().ToHashSet();

        Assert.All(
            Enum.GetValues<Capability>(),
            capability => Assert.Contains(capability, detected));
    }

    /// <summary>Both phrasings are written for every value, rather than falling back to the name.</summary>
    [Theory]
    [MemberData(nameof(AllCapabilities))]
    public void Every_capability_is_phrased_for_a_reader(Capability capability)
    {
        Assert.NotEqual(capability.ToString(), capability.Humanise());
        Assert.NotEqual("an application of some other kind", capability.ExpectedOf());
    }

    public static TheoryData<Capability> AllCapabilities
    {
        get
        {
            var data = new TheoryData<Capability>();

            foreach (var capability in Enum.GetValues<Capability>())
            {
                data.Add(capability);
            }

            return data;
        }
    }

    // ---- The tag survives the trip through the engine ------------------------

    private static IReadOnlyList<Finding> Scan(string content, string path) =>
        new RuleEngine().Analyse(
        [
            new RecoveredFile
            {
                RelativePath = path,
                Content = content,
                Language = RecoveredFile.LanguageOf(path),
            },
        ]).Findings;

    [Fact]
    public void A_finding_carries_the_capability_of_the_rule_that_raised_it()
    {
        var finding = Assert.Single(
            Scan("""const db = open("cookies.sqlite");""", "src/clean.js"),
            f => f.RuleId == "VC-MAL-002");

        Assert.Equal(Capability.BrowserCookies, finding.Capability);
    }

    /// <summary>
    /// Softening a finding found in a fixture rewrites it, and a rewrite that dropped the tag
    /// would quietly make that finding unexplainable by any purpose.
    /// </summary>
    [Fact]
    public void Softening_a_test_file_finding_keeps_the_capability()
    {
        var finding = Assert.Single(
            Scan("""const db = open("cookies.sqlite");""", "src/__mocks__/clean.js"),
            f => f.RuleId == "VC-MAL-002");

        Assert.False(finding.IsBlocking);
        Assert.Equal(Capability.BrowserCookies, finding.Capability);
    }
}
