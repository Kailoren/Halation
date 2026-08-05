namespace VibeCheck.Core.Model;

/// <summary>Who said the application has a reason for a capability.</summary>
/// <remarks>
/// Recorded rather than assumed, because the two are not worth the same. A person deciding
/// whether to run something has weighed it; a file inside the download has not, and an
/// application that wanted to look harmless would ship exactly such a file.
/// </remarks>
public enum PurposeSource
{
    /// <summary>The person running the scan affirmed it.</summary>
    Reader,

    /// <summary>
    /// A manifest inside the artifact claimed it. Never sufficient on its own: it arrived with
    /// the untrusted thing being examined, so it can populate the question but not answer it.
    /// </summary>
    Manifest,
}

/// <summary>
/// What this application has been said to have a reason to do.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a set of capabilities rather than a kind of application. Naming kinds was tried
/// on paper first and fails twice over: the list has no natural end, since there is no end to
/// the kinds of software in the world, and picking a flattering label off a list is both easy
/// and deniable. Affirming that <i>this application has a reason to read browser cookies</i> is
/// a specific claim about a specific observed behaviour, and the report can print it back.
/// </para>
/// <para>
/// It never lowers a severity and never deletes a finding. It moves one out of the arithmetic
/// and into the list of what the application can do, with the affirmation attached. An
/// application that had a reason for everything therefore produces a report saying so, which is
/// the most useful thing such a report could say.
/// </para>
/// </remarks>
public sealed record DeclaredPurpose
{
    /// <summary>Capabilities this application has been said to have a reason for.</summary>
    public IReadOnlySet<Capability> Accounted { get; init; } = new HashSet<Capability>();

    /// <summary>Who said so.</summary>
    public required PurposeSource Source { get; init; }

    /// <summary>Nothing has been said, which is the default and the strict reading.</summary>
    public static DeclaredPurpose None { get; } = new() { Source = PurposeSource.Reader };

    /// <summary>What the person running the scan affirmed.</summary>
    public static DeclaredPurpose FromReader(params Capability[] accounted) => new()
    {
        Accounted = new HashSet<Capability>(accounted),
        Source = PurposeSource.Reader,
    };

    public bool Accounts(Capability capability) => Accounted.Contains(capability);

    public bool SaysAnything => Accounted.Count > 0;

    /// <summary>
    /// How the affirmation is phrased where a reader sees it, including in an exported report
    /// somebody else is looking at.
    /// </summary>
    /// <remarks>
    /// Written in the second person and naming the behaviour, so that a screenshot of a quiet
    /// report still shows exactly what was waved through and on whose say-so. A label like
    /// "Cleaner" would have shown neither.
    /// </remarks>
    public string Attribution(Capability capability) => Source switch
    {
        PurposeSource.Reader =>
            $"You told VibeCheck this application has a reason to {Lowered(capability)}.",
        PurposeSource.Manifest =>
            $"The application's own manifest claims a reason to {Lowered(capability)}.",
        _ => $"Something accounted for the ability to {Lowered(capability)}.",
    };

    private static string Lowered(Capability capability)
    {
        var phrase = capability.Humanise();

        return char.ToLowerInvariant(phrase[0]) + phrase[1..];
    }
}

/// <summary>
/// Sorts observed findings into what counts against an application and what it can do.
/// </summary>
/// <remarks>
/// One place, used both by a fresh scan and by re-answering an existing one, so the two can
/// never disagree about what a declaration did.
/// </remarks>
public static class PurposeSplit
{
    /// <summary>
    /// Splits into the findings that are scored and the capabilities that are only reported.
    /// </summary>
    /// <remarks>
    /// Three cases. A rule that reports a capability by nature is one whatever anybody says. A
    /// finding naming a capability that has been accounted for becomes one, carrying who said
    /// so. Everything else stays a finding, including every rule that names no capability,
    /// which is what keeps a declaration from reaching a leaked key or a dropper.
    /// </remarks>
    public static (IReadOnlyList<Finding> Findings, IReadOnlyList<Finding> Capabilities) Apply(
        IReadOnlyList<Finding> observed,
        DeclaredPurpose? purpose)
    {
        ArgumentNullException.ThrowIfNull(observed);

        var findings = new List<Finding>();
        var capabilities = new List<Finding>();

        foreach (var finding in observed)
        {
            if (finding.IsCapability)
            {
                capabilities.Add(finding);
                continue;
            }

            // Always written, never left over. Re-answering a report with a narrower
            // declaration has to be able to take an explanation away again.
            if (finding.Capability is { } capability && purpose?.Accounts(capability) == true)
            {
                capabilities.Add(finding with { ExplainedBy = purpose.Source });
                continue;
            }

            findings.Add(finding.ExplainedBy is null ? finding : finding with { ExplainedBy = null });
        }

        return (findings, capabilities);
    }
}
