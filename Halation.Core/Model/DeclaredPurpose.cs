namespace Halation.Core.Model;

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

    /// <summary>
    /// A comment in the source explained it, found by the deep pass.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Same trust level as <see cref="Manifest"/>, and for the same reason: a comment ships
    /// inside the thing under examination, so an application that wanted to look harmless would
    /// carry exactly such a comment. It populates the question and never answers it.
    /// </para>
    /// <para>
    /// Worth having anyway, because the developer case is the one where it is almost always
    /// true. Asking somebody "does this have a reason to read cookies?" when their own code says
    /// two lines above that it is clearing stale sessions is asking them to retype what they
    /// already wrote. It only exists when scanning source: decompilation destroys comments, which
    /// is exactly the asymmetry measured on FleetFinder.
    /// </para>
    /// </remarks>
    SourceComment,
}

/// <summary>Which sources are allowed to settle a question rather than merely raise it.</summary>
public static class PurposeSources
{
    /// <summary>
    /// Whether a claim from this source may account for a capability on its own.
    /// </summary>
    /// <remarks>
    /// <b>Only the reader.</b> Everything else arrived inside the artifact being examined and
    /// therefore carries no weight it did not give itself. This was documented on
    /// <see cref="PurposeSource.Manifest"/> from the start and enforced nowhere:
    /// <see cref="PurposeSplit"/> asked only whether a capability was in the set, so any
    /// non-reader purpose carrying one would have accounted for it silently. Latent rather than
    /// live, because nothing constructed one. Adding a second untrusted source is exactly how a
    /// latent hole becomes a real one.
    /// </remarks>
    public static bool CanAccount(this PurposeSource source) => source == PurposeSource.Reader;
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

    /// <summary>
    /// What kind of application this was said to be.
    /// </summary>
    /// <remarks>
    /// Carried here so it reaches the report without a second channel, and so a screenshot of a
    /// quiet result shows the declaration that framed the questions as well as the answers. It
    /// accounts for nothing on its own: see <see cref="ApplicationKind"/>.
    /// </remarks>
    public ApplicationKind Kind { get; init; } = ApplicationKind.Unstated;

    /// <summary>Nothing has been said, which is the default and the strict reading.</summary>
    public static DeclaredPurpose None { get; } = new() { Source = PurposeSource.Reader };

    /// <summary>What the person running the scan affirmed.</summary>
    public static DeclaredPurpose FromReader(params Capability[] accounted) => new()
    {
        Accounted = new HashSet<Capability>(accounted),
        Source = PurposeSource.Reader,
    };

    /// <summary>What they affirmed, and what they said the application is.</summary>
    public static DeclaredPurpose FromReader(
        ApplicationKind kind, IEnumerable<Capability> accounted) => new()
    {
        Accounted = new HashSet<Capability>(accounted),
        Source = PurposeSource.Reader,
        Kind = kind,
    };

    /// <summary>
    /// The declaration itself, for the report to print back.
    /// </summary>
    /// <remarks>
    /// Null when nobody said, rather than "Not stated", so a report that was never answered says
    /// nothing rather than saying something empty.
    /// </remarks>
    public string? KindAttribution => Kind is ApplicationKind.Unstated
        ? null
        : $"You told VibeCheck this is {Kind.InSentence()}.";

    /// <summary>
    /// Whether this declaration settles the question for a capability.
    /// </summary>
    /// <remarks>
    /// Membership is not enough. A claim that came out of the artifact can raise the question
    /// and populate the answer for somebody to confirm, but only the reader's own affirmation
    /// takes a finding out of the arithmetic. See <see cref="PurposeSources.CanAccount"/>.
    /// </remarks>
    public bool Accounts(Capability capability) =>
        Source.CanAccount() && Accounted.Contains(capability);

    /// <summary>
    /// What this declaration claims, whether or not it is allowed to settle anything.
    /// </summary>
    /// <remarks>
    /// This is the half a prefill uses: the deep pass reporting that the source explains a
    /// capability should put that in front of the reader, not past them.
    /// </remarks>
    public bool Claims(Capability capability) => Accounted.Contains(capability);

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
            $"The application's own manifest claims a reason to {Lowered(capability)}. That "
            + "came from inside the application, so it is worth knowing and is not confirmation.",
        PurposeSource.SourceComment =>
            $"The source says this is to {Lowered(capability)}. That is the author's own note "
            + "rather than an independent check, so it explains the code without vouching for it.",
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
