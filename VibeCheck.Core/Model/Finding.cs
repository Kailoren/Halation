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

    public required Severity Severity { get; init; }

    public required FindingCategory Category { get; init; }

    /// <summary>What the problem is and why it matters, in plain language.</summary>
    public required string Description { get; init; }

    /// <summary>Concrete steps to fix it. Absent only where no general remedy applies.</summary>
    public string? Remediation { get; init; }

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

    /// <summary>Reference URL, e.g. a CVE or vendor advisory.</summary>
    public string? Reference { get; init; }

    /// <summary>Where in the file this occurred, formatted for display.</summary>
    public string Location => FilePath is null
        ? "(artifact)"
        : Line is null ? FilePath : $"{FilePath}:{Line}";
}
