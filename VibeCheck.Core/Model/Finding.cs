namespace VibeCheck.Core.Model;

/// <summary>
/// One issue detected in the scanned artifact.
/// </summary>
public sealed record Finding
{
    /// <summary>Stable identifier for the rule that fired, e.g. "VC-SEC-001".</summary>
    public required string RuleId { get; init; }

    /// <summary>Short headline, written for a developer skimming a list.</summary>
    public required string Title { get; init; }

    /// <summary>
    /// How bad this is for the person shipping the application.
    /// </summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// How bad this is for the person running the application, which is routinely not the
    /// same answer.
    /// </summary>
    /// <remarks>
    /// Required rather than defaulted, so that adding a rule forces the judgment. A silent
    /// fallback to <see cref="Severity"/> would quietly file every developer-side problem as
    /// the end user's problem too, which is the failure this whole split exists to prevent.
    /// Producers that genuinely cannot distinguish, such as a CVE advisory, set both to the
    /// same value deliberately.
    /// </remarks>
    public required Severity UserSeverity { get; init; }

    public required FindingCategory Category { get; init; }

    /// <summary>What the problem is and why it matters, for whoever wrote the code.</summary>
    public required string Description { get; init; }

    /// <summary>
    /// The same finding told to someone who did not write the application and cannot change
    /// it: what it could mean for them, and what they can do about it.
    /// </summary>
    /// <remarks>
    /// Not a simplification of <see cref="Description"/>. It answers a different question,
    /// and for a large class of findings the honest answer is that this is the author's
    /// problem rather than the reader's.
    /// </remarks>
    public required string UserDescription { get; init; }

    /// <summary>
    /// Concrete steps to fix it, for the person who can. Absent only where no general remedy
    /// applies.
    /// </summary>
    public string? Remediation { get; init; }

    /// <summary>
    /// What the reader can do when they cannot change the code. Frequently null, because
    /// frequently there is nothing, and inventing reassurance would be worse than silence.
    /// </summary>
    public string? UserRemediation { get; init; }

    /// <summary>Path relative to the recovery root, so reports do not leak local paths.</summary>
    public string? FilePath { get; init; }

    /// <summary>1-indexed line within <see cref="FilePath"/>.</summary>
    public int? Line { get; init; }

    /// <summary>
    /// The matching snippet, for the reader to judge the finding themselves.
    /// </summary>
    /// <remarks>
    /// Must already be redacted by the producer. A report that quotes a live API key in
    /// full is itself a disclosure, and reports get pasted into issues and chat.
    /// </remarks>
    public string? Evidence { get; init; }

    public FindingSource Source { get; init; } = FindingSource.Rule;

    /// <summary>
    /// Whether this finding alone justifies telling the user not to install the artifact.
    /// Set only by specific high-confidence deterministic rules; see ScoreCalculator, which
    /// ignores this flag on <see cref="FindingSource.Assisted"/> findings regardless.
    /// </summary>
    public bool IsBlocking { get; init; }

    /// <summary>
    /// Whether this describes something the application <i>can do</i> rather than something it
    /// does wrong.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Auto-updating and starting with Windows are how a great many correct programs work. Rated
    /// as defects they were charging a working application a band of score for having a feature,
    /// and one High is enough to relabel it as having serious issues, which is how a scanner
    /// teaches people to stop reading it.
    /// </para>
    /// <para>
    /// They are still worth reporting, and to somebody deciding whether to run a download they
    /// may be the most useful part: an application that replaces its own code is one whose future
    /// behaviour no scan of it can describe. So they are listed and explained, in their own
    /// section, and kept out of the arithmetic entirely.
    /// </para>
    /// </remarks>
    public bool IsCapability { get; init; }

    /// <summary>
    /// The power this finding demonstrates, when it is one a declared purpose could account
    /// for. Null for everything that is wrong whatever the application is for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Distinct from <see cref="IsCapability"/>, and the two compose rather than compete.
    /// <see cref="IsCapability"/> says how this finding is treated: reported and never scored.
    /// This says which power it is evidence of. A finding may carry one, both or neither: an
    /// auto-start observation is both, a cookie-database read is currently a scored defect that
    /// names a power, and a leaked API key is neither.
    /// </para>
    /// <para>
    /// Set here so that nothing downstream has to infer intent from a rule identifier. See
    /// <see cref="Model.Capability"/> for why most rules leave it null.
    /// </para>
    /// </remarks>
    public Capability? Capability { get; init; }

    /// <summary>Reference URL, e.g. a CVE or vendor advisory.</summary>
    public string? Reference { get; init; }

    /// <summary>Where in the file this occurred, formatted for display.</summary>
    public string Location => FilePath is null
        ? "(artifact)"
        : Line is null ? FilePath : $"{FilePath}:{Line}";

    public Severity SeverityFor(Audience audience) =>
        audience == Audience.EndUser ? UserSeverity : Severity;

    public string DescriptionFor(Audience audience) =>
        audience == Audience.EndUser ? UserDescription : Description;

    public string? RemediationFor(Audience audience) =>
        audience == Audience.EndUser ? UserRemediation : Remediation;

    /// <summary>
    /// Whether this finding bears on the given reader's decision.
    /// </summary>
    /// <remarks>
    /// <see cref="Severity.Info"/> is how a finding says "not your problem" without being
    /// hidden: it deducts nothing and never caps the score, but it is still shown, because
    /// telling an end user that the leaked key is the author's rather than theirs is more
    /// useful than silently dropping it and leaving them to wonder what the scanner saw.
    /// </remarks>
    public bool AffectsDecisionOf(Audience audience) => SeverityFor(audience) > Severity.Info;
}
