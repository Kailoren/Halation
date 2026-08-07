namespace Halation.Core.Model;

/// <summary>
/// What the letters in a rule identifier mean.
/// </summary>
/// <remarks>
/// <para>
/// A report full of codes like <c>VC-MAL-003</c> asks the reader to take on trust that the
/// scanner has a filing system. The identifier is genuinely useful, being the thing to quote in
/// a bug report and the thing to search for, but only once it is legible: until then it is
/// decoration that makes a finding look more official than the sentence beside it.
/// </para>
/// <para>
/// Phrased once here so the window, the tooltip and the exported report cannot drift apart.
/// </para>
/// </remarks>
public static class RuleFamily
{
    /// <summary>The family a rule identifier belongs to, or null when it is not one of ours.</summary>
    public static string? PrefixOf(string? ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return null;
        }

        var parts = ruleId.Split('-');

        return parts.Length >= 2 && parts[0].Equals("VC", StringComparison.OrdinalIgnoreCase)
            ? parts[1].ToUpperInvariant()
            : null;
    }

    /// <summary>A short name for the family, for a heading or a chip.</summary>
    public static string NameOf(string? ruleId) => PrefixOf(ruleId) switch
    {
        "SEC" => "Secrets",
        "CODE" => "Code safety",
        "INPUT" => "Untrusted input",
        "CFG" => "Configuration",
        "MAL" => "Malicious behaviour",
        "DEP" => "Dependencies",
        "PKG" => "Packaging",
        "BIN" => "Binary hygiene",
        "DUP" => "Duplication",
        "AI" => "Deep pass",
        _ => "Finding",
    };

    /// <summary>
    /// What the family covers, in a sentence, for the reader who wondered what the code means.
    /// </summary>
    /// <remarks>
    /// Written to answer "why is this being shown to me" rather than to define a taxonomy. Each
    /// says what the checks in it look for and, where it is not obvious, what the family cannot
    /// tell you.
    /// </remarks>
    public static string DescribeOf(string? ruleId) => PrefixOf(ruleId) switch
    {
        "SEC" =>
            "Credentials written into the application itself: API keys, tokens, private "
            + "keys and passwords. Anything shipped is readable by whoever has the file, so a key "
            + "here should be treated as already public and rotated rather than removed quietly.",

        "CODE" =>
            "Ways of writing something that are dangerous however carefully they are "
            + "used: queries built by joining strings, commands assembled from values, unsafe "
            + "deserialisation, broken ciphers, and randomness that is predictable.",

        "INPUT" =>
            "Places where something from outside the application, a file, a "
            + "network response, or a link, reaches an operation that assumed it was safe. These "
            + "depend on whether a guard exists somewhere the scanner could not see, so they are "
            + "the family most worth checking against the quoted line.",

        "CFG" =>
            "Settings that weaken the application without changing a line of its "
            + "logic: certificate checks switched off, obsolete protocols forced, permissions left "
            + "open, debug mode shipped, or a service listening more widely than it needs to.",

        "MAL" =>
            "Things with few honest uses in ordinary software, such as "
            + "reading saved browser passwords, session cookies or cryptocurrency wallets. These "
            + "are the only checks that can advise against installing on their own, which is why "
            + "they are written to be certain rather than suggestive.",

        "DEP" =>
            "Published advisories against the exact package versions this "
            + "application ships, matched at the moment of the scan rather than from a bundled "
            + "list. Says nothing about how the application uses the package, so a flaw listed "
            + "here may or may not be reachable in this program.",

        "PKG" =>
            "What ended up in the release that should not have: debug symbols, source "
            + "maps, development configuration, or files that were never meant to ship. Rarely "
            + "dangerous on its own, and usually a sign of how the build was assembled.",

        "BIN" =>
            "Properties of the compiled file rather than its code: whether it is "
            + "signed, whether protections the compiler offers were switched on, and what it "
            + "claims about its own origin.",

        "DUP" =>
            "Repeated blocks, copied files and commented-out code. Always "
            + "informational and never counted towards the score, because it describes what the "
            + "application costs to maintain rather than what it puts at risk.",

        "AI" =>
            "Found by a model reading the code rather than by a pattern matching it, "
            + "which is what allows it to judge whether a guard is complete or whether untrusted "
            + "input can actually reach a dangerous call. Reasoned rather than matched, so each "
            + "one quotes the code it rests on and none of them alone can advise against "
            + "installing.",

        _ => "A check this scanner ran.",
    };

    /// <summary>The identifier and its meaning together, as a tooltip shows it.</summary>
    public static string Tooltip(string? ruleId) =>
        string.IsNullOrWhiteSpace(ruleId) || PrefixOf(ruleId) is null
            ? DescribeOf(ruleId)
            : $"{ruleId}  ·  {NameOf(ruleId)}\n\n{DescribeOf(ruleId)}";
}
