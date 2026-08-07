using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.Rules;

/// <summary>
/// One recovered file, prepared for rule evaluation.
/// </summary>
/// <remarks>
/// Line offsets are computed once per file and shared by every rule, rather than each rule
/// rescanning the text to work out where its match landed.
/// </remarks>
public sealed class RuleContext
{
    private readonly int[] _lineStarts;

    public RuleContext(RecoveredFile file)
    {
        ArgumentNullException.ThrowIfNull(file);

        File = file;

        var starts = new List<int> { 0 };
        for (var i = 0; i < file.Content.Length; i++)
        {
            if (file.Content[i] == '\n')
            {
                starts.Add(i + 1);
            }
        }

        _lineStarts = [.. starts];
    }

    public RecoveredFile File { get; }

    public string Content => File.Content;

    /// <summary>1-indexed line containing the given character offset.</summary>
    public int LineAt(int offset)
    {
        var index = Array.BinarySearch(_lineStarts, offset);
        return (index >= 0 ? index : ~index - 1) + 1;
    }

    /// <summary>Where a file offset sits within its own line, for line-scoped analysis.</summary>
    public int OffsetInLine(int offset)
    {
        var index = LineAt(offset) - 1;

        return index >= 0 && index < _lineStarts.Length ? offset - _lineStarts[index] : 0;
    }

    /// <summary>
    /// How much of a line counts as one place, for deciding whether two matches describe the
    /// same thing.
    /// </summary>
    /// <remarks>
    /// Sized so an ordinary line is always one region and never splits, which is what keeps
    /// this invisible on hand-written code. Same figure, for the same reason, as the average
    /// line length past which <see cref="Heuristics"/> stops treating a file as written in
    /// lines at all.
    /// </remarks>
    public const int RegionWidth = 200;

    /// <summary>
    /// The place a match sits, as somewhere two matches can be judged to coincide.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The line, plus which stretch of it, and the second half is the part that matters. Rules
    /// report once per line because a rule matching twice on one line is describing a single
    /// problem. That reasoning holds for a line of code and fails completely for a minified
    /// bundle, where the file is one line: the same rule matching in twenty unrelated places
    /// collapsed to a single finding.
    /// </para>
    /// <para>
    /// Measured on a real application. Taking a readable bundle, removing only its line breaks
    /// and changing nothing else, took VC-MAL-002 from six findings to one, VC-MAL-006 from
    /// twenty to one and VC-MAL-007 from twenty to one, with the raw match counts identical
    /// throughout. The score moved from 13 to 29 on byte-identical code, because weight
    /// accumulates per finding. Minification is not something a scan should be able to score
    /// its way out of.
    /// </para>
    /// <para>
    /// On any normally formatted line the region is always zero and the key is the line number
    /// exactly as before, so nothing about hand-written code changes.
    /// </para>
    /// </remarks>
    public (int Line, int Region) PlaceOf(int offset) =>
        (LineAt(offset), OffsetInLine(offset) / RegionWidth);

    private bool? _patternCatalogue;

    /// <summary>
    /// Whether this file reads as a catalogue of detection patterns rather than code.
    /// </summary>
    /// <remarks>
    /// Computed once and reused by every rule, because it is a property of the file and the
    /// whole catalog asks about it. Safe to cache without a lock: one context serves one file
    /// on one thread. See <see cref="Heuristics.IsPatternDefinition"/> for what it is for.
    /// </remarks>
    public bool IsPatternCatalogue =>
        _patternCatalogue ??= Heuristics.CountsAsPatternCatalogue(Content);

    /// <summary>
    /// Matches dropped as pattern definitions rather than uses.
    /// </summary>
    /// <remarks>
    /// Counted rather than merely dropped, so the scan can say it discounted them. Silently
    /// removing findings is the one thing a tool built on saying what it did must not do.
    /// </remarks>
    public int DiscountedMatches { get; private set; }

    internal void Discount() => DiscountedMatches++;

    /// <summary>The full text of a 1-indexed line, without its terminator.</summary>
    public string LineText(int lineNumber)
    {
        var index = lineNumber - 1;
        if (index < 0 || index >= _lineStarts.Length)
        {
            return string.Empty;
        }

        var start = _lineStarts[index];
        var end = index + 1 < _lineStarts.Length ? _lineStarts[index + 1] : Content.Length;

        return Content[start..end].TrimEnd('\r', '\n');
    }

    /// <summary>The line a match landed on, for use as evidence.</summary>
    public string LineFor(Match match) => LineText(LineAt(match.Index));
}

/// <summary>A single check applied to recovered source.</summary>
public interface IRule
{
    string Id { get; }

    /// <summary>
    /// What this check looks for, in the words used when reporting that it passed.
    /// </summary>
    /// <remarks>
    /// On the interface rather than only on the concrete rule, because the report now lists
    /// every check and its outcome, not only the ones that fired. A check with no name cannot
    /// appear in that list, and a check missing from that list is indistinguishable from one
    /// that was never written.
    /// </remarks>
    string Title { get; }

    FindingCategory Category { get; }

    bool AppliesTo(RecoveredFile file);

    IEnumerable<Finding> Examine(RuleContext context);
}

/// <summary>
/// A rule expressed as a regular expression over source text.
/// </summary>
/// <remarks>
/// Rules are data rather than subclasses, so the catalog reads as a list of checks and
/// adding one does not mean adding a type. Every pattern is constructed with a match
/// timeout: the input is untrusted by definition, and an unbounded backtracking regex over
/// hostile text is a denial of service in the scanner itself.
/// </remarks>
public sealed class PatternRule : IRule
{
    /// <summary>Ceiling on a single regex evaluation. Deliberately short.</summary>
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    public required string Id { get; init; }

    public required string Title { get; init; }

    /// <summary>How bad this is for whoever ships the application.</summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// How bad this is for whoever runs it. Required, so adding a rule cannot skip the
    /// judgment and silently inherit the developer's answer.
    /// </summary>
    public required Severity UserSeverity { get; init; }

    public required FindingCategory Category { get; init; }

    public required string Description { get; init; }

    /// <summary>The same finding written for someone who cannot change the code.</summary>
    public required string UserDescription { get; init; }

    public required string Remediation { get; init; }

    /// <summary>
    /// What the reader can do about it when it is not their code. Null where there is
    /// genuinely nothing, which is common and better said by omission than by padding.
    /// </summary>
    public string? UserRemediation { get; init; }

    public required Regex Pattern { get; init; }

    /// <summary>Languages this rule applies to. Null means every recovered file.</summary>
    public SourceLanguage[]? Languages { get; init; }

    /// <summary>Only consider files whose path satisfies this, when set.</summary>
    public Func<string, bool>? PathFilter { get; init; }

    /// <summary>
    /// Capture group holding the sensitive value, so it can be masked in the evidence.
    /// </summary>
    public string? SecretGroup { get; init; }

    /// <summary>Suppresses a match that is a known false positive.</summary>
    public Func<Match, RuleContext, bool>? Ignore { get; init; }

    /// <summary>
    /// Whether a match justifies advising against installation on its own. Reserved for
    /// high-confidence rules where the consequence is unambiguous.
    /// </summary>
    public bool IsBlocking { get; init; }

    /// <summary>
    /// Whether this rule reports a capability rather than a defect. See
    /// <see cref="Finding.IsCapability"/>.
    /// </summary>
    public bool IsCapability { get; init; }

    /// <summary>
    /// The power a match demonstrates, when a declared purpose could account for it. Left unset
    /// by every rule describing something wrong whatever the application is for. See
    /// <see cref="Model.Capability"/>.
    /// </summary>
    public Capability? Capability { get; init; }

    public string? Reference { get; init; }

    /// <summary>Cap per rule per file, so one pathological file cannot flood the report.</summary>
    public int MaxMatchesPerFile { get; init; } = 20;

    public bool AppliesTo(RecoveredFile file)
    {
        ArgumentNullException.ThrowIfNull(file);

        if (Languages is not null && !Languages.Contains(file.Language))
        {
            return false;
        }

        return PathFilter is null || PathFilter(file.RelativePath);
    }

    public IEnumerable<Finding> Examine(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();
        var seenPlaces = new HashSet<(int Line, int Region)>();

        MatchCollection matches;
        try
        {
            matches = Pattern.Matches(context.Content);
        }
        catch (RegexMatchTimeoutException)
        {
            // Treated as "this rule could not complete here", not as a clean result. The
            // engine records it so coverage stays honest.
            throw new RuleTimeoutException(Id, context.File.RelativePath);
        }

        foreach (Match match in matches)
        {
            if (findings.Count >= MaxMatchesPerFile)
            {
                break;
            }

            // Ahead of the rule's own Ignore, because this is not a false positive the rule
            // could have anticipated: it is the scanner reading a table of detection patterns
            // and taking each entry for the thing it detects. Secrets are exempt, as everywhere
            // else, because a credential in quotation marks is a leaked credential.
            if (Category != FindingCategory.Secrets
                && Heuristics.IsPatternDefinition(context, match.Index))
            {
                context.Discount();
                continue;
            }

            if (Ignore?.Invoke(match, context) == true)
            {
                continue;
            }

            var line = context.LineAt(match.Index);

            // One finding per place: a rule that matches twice in the same place is reporting
            // one problem, and duplicates make a report look padded. A place is a line, except
            // in a bundle where the file is one line and that would mean the whole file. See
            // RuleContext.PlaceOf.
            if (!seenPlaces.Add(context.PlaceOf(match.Index)))
            {
                continue;
            }

            var secret = SecretGroup is not null && match.Groups[SecretGroup].Success
                ? match.Groups[SecretGroup].Value
                : null;

            findings.Add(new Finding
            {
                RuleId = Id,
                Title = Title,
                Severity = Severity,
                UserSeverity = UserSeverity,
                Category = Category,
                Description = Description,
                UserDescription = UserDescription,
                Remediation = Remediation,
                UserRemediation = UserRemediation,
                FilePath = context.File.RelativePath,
                Line = line,
                Column = context.OffsetInLine(match.Index),
                Evidence = Redaction.BuildEvidence(context.LineText(line), secret),
                IsBlocking = IsBlocking,
                IsCapability = IsCapability,
                Capability = Capability,
                Reference = Reference,
                Source = FindingSource.Rule,
            });
        }

        return findings;
    }

    /// <summary>Builds a pattern with the mandatory timeout and standard options applied.</summary>
    public static Regex Compile(string pattern, RegexOptions options = RegexOptions.None) =>
        new(pattern, options | RegexOptions.Compiled | RegexOptions.Multiline, MatchTimeout);
}

/// <summary>Raised when a rule exceeds its evaluation budget on a specific file.</summary>
public sealed class RuleTimeoutException(string ruleId, string filePath) : Exception(
    $"Rule {ruleId} timed out on {filePath}.")
{
    public string RuleId { get; } = ruleId;

    public string FilePath { get; } = filePath;
}
