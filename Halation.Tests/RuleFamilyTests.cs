using Halation.Core.Model;
using Halation.Core.Rules;

namespace Halation.Tests;

/// <summary>
/// The glossary behind the identifiers.
/// </summary>
/// <remarks>
/// A code like VC-MAL-003 asks the reader to take the filing system on trust. It is worth
/// showing, being the thing to quote in a bug report and the thing to search for, but a family
/// with no description is decoration that makes a finding look more official than the sentence
/// beside it.
/// </remarks>
public class RuleFamilyTests
{
    [Theory]
    [InlineData("VC-SEC-003", "SEC", "Secrets")]
    [InlineData("VC-CODE-001", "CODE", "Code safety")]
    [InlineData("VC-INPUT-002", "INPUT", "Untrusted input")]
    [InlineData("VC-MAL-007", "MAL", "Malicious behaviour")]
    [InlineData("VC-CFG-005", "CFG", "Configuration")]
    [InlineData("VC-DEP-001", "DEP", "Dependencies")]
    [InlineData("VC-PKG-001", "PKG", "Packaging")]
    [InlineData("VC-BIN-001", "BIN", "Binary hygiene")]
    [InlineData("VC-DUP-002", "DUP", "Duplication")]
    [InlineData("VC-AI-001", "AI", "Deep pass")]
    public void Reads_the_family_out_of_an_identifier(string ruleId, string prefix, string name)
    {
        Assert.Equal(prefix, RuleFamily.PrefixOf(ruleId));
        Assert.Equal(name, RuleFamily.NameOf(ruleId));
        Assert.True(RuleFamily.DescribeOf(ruleId).Length > 80, "a family deserves a real sentence");
    }

    /// <summary>
    /// The check that matters: a family added to the catalogue without a description here would
    /// show a reader a code and then decline to say what it meant.
    /// </summary>
    [Fact]
    public void Every_family_in_the_catalogue_is_described()
    {
        var families = RuleEngine.DefaultRules
            .Select(rule => RuleFamily.PrefixOf(rule.Id))
            .Where(prefix => prefix is not null)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(families);

        foreach (var family in families)
        {
            var id = $"VC-{family}-001";

            Assert.NotEqual("Finding", RuleFamily.NameOf(id));
            Assert.NotEqual("A check this scanner ran.", RuleFamily.DescribeOf(id));
        }
    }

    /// <summary>
    /// Every rule identifier in the catalogue has to parse, or its finding shows the fallback
    /// text in a tooltip and nobody notices until a reader hovers it.
    /// </summary>
    [Fact]
    public void Every_rule_identifier_parses()
    {
        foreach (var rule in RuleEngine.DefaultRules)
        {
            Assert.NotNull(RuleFamily.PrefixOf(rule.Id));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-rule")]
    [InlineData("VC")]
    public void Anything_that_is_not_an_identifier_falls_back_quietly(string? ruleId)
    {
        Assert.Null(RuleFamily.PrefixOf(ruleId));
        Assert.Equal("A check this scanner ran.", RuleFamily.DescribeOf(ruleId));

        // And the tooltip is the description alone, with no orphaned separator.
        Assert.DoesNotContain("·", RuleFamily.Tooltip(ruleId), StringComparison.Ordinal);
    }

    [Fact]
    public void The_tooltip_leads_with_the_identifier_and_its_name()
    {
        var tooltip = RuleFamily.Tooltip("VC-SEC-003");

        Assert.StartsWith("VC-SEC-003", tooltip, StringComparison.Ordinal);
        Assert.Contains("Secrets", tooltip, StringComparison.Ordinal);
        Assert.Contains(RuleFamily.DescribeOf("VC-SEC-003"), tooltip, StringComparison.Ordinal);
    }
}
