using System.Text.RegularExpressions;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Handling of data that arrives from somewhere the application does not control.
/// </summary>
/// <remarks>
/// <para>
/// These rules come from real findings in hand-audited desktop applications rather than from
/// a generic vulnerability list, and they cover a gap the OWASP-shaped checks miss. A desktop
/// application that parses a public data feed, a pasted import file, or an API response has a
/// genuine attacker-reachable input path, but no web request to model it as, so this class of
/// bug goes unlooked-for.
/// </para>
/// <para>
/// The pattern each rule encodes: a value taken from that input is used to size an
/// allocation, drive a conversion that can throw, or launch something, without a bound or a
/// check in between.
/// </para>
/// </remarks>
public static class UntrustedInputRules
{
    /// <summary>
    /// Recognises a scheme or host check ahead of a launch, in any of the usual spellings.
    /// Declared before the rules that reference it so static initialisation sees it set.
    /// </summary>
    private static readonly Regex SchemeValidation = PatternRule.Compile(
        """
        Uri\.TryCreate
        |UriSchemeHttps
        |\.Scheme\s*(?:!=|==)
        |\.Host\s*(?:\.Equals|!=|==)
        |StartsWith\s*\(\s*"https://
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <inheritdoc cref="SecretRules.All"/>
    public static IReadOnlyList<IRule> All =>
    [
        UnboundedStackAllocation,
        ShellOpenOfDynamicUrl,
        UnguardedNumericParse,
        UnboundedRemoteRead,
    ];

    /// <summary>
    /// Reading an entire remote response into memory with no size limit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These calls materialise the whole response before the caller sees any of it, so there
    /// is no point at which a length can be checked. The size is decided by whoever answers
    /// the request. That is fine against an endpoint the application controls and is a hole
    /// against any third-party API, because the trust assumption is invisible at the call
    /// site: the same line is correct or wrong depending only on what it points at.
    /// </para>
    /// <para>
    /// Found by scanning a hand-audited application that had already been through a security
    /// pass. It capped responses from its own service and read a third-party API with no cap
    /// at all, which is the wrong way round, and the unbounded string then fed a stackalloc.
    /// Neither half was noticed by review.
    /// </para>
    /// </remarks>
    private static PatternRule UnboundedRemoteRead { get; } = new()
    {
        Id = "VC-INPUT-004",
        Title = "Reads an entire remote response with no size limit",
        Severity = Severity.Medium,
        Category = FindingCategory.Network,
        Description =
            "The response body is read into a single string or array in one call, so its size is "
            + "whatever the remote end chooses to send. A large or endless reply becomes memory "
            + "the application cannot refuse, and anything derived from that value carries the "
            + "same unbounded length onwards.",
        Remediation =
            "Read the body as a stream and copy it with a byte ceiling, failing once the ceiling "
            + "is passed. Checking the Content-Length header instead is not equivalent: it is "
            + "absent on chunked responses and is supplied by the sender either way, so the limit "
            + "has to be enforced while reading rather than before it.",
        Pattern = PatternRule.Compile(
            """
            \.(?:GetStringAsync
            |GetByteArrayAsync
            |ReadAsStringAsync
            |ReadAsByteArrayAsync
            |DownloadString(?:TaskAsync)?
            |DownloadData(?:TaskAsync)?)\s*\(
            """,
            RegexOptions.IgnorePatternWhitespace),
        Languages = [SourceLanguage.CSharp],
        Ignore = (match, context) => Heuristics.IsInLineComment(context, match.Index),
    };

    /// <summary>
    /// Stack allocation sized from a variable.
    /// </summary>
    /// <remarks>
    /// This was the headline finding of a real audit: a <c>stackalloc</c> sized from a string
    /// arriving on a public data firehose, giving anyone able to publish to that feed a
    /// remote crash of every client. The stack is small and cannot be recovered from, so an
    /// overflow terminates the process outright rather than raising a catchable exception.
    /// </remarks>
    private static PatternRule UnboundedStackAllocation { get; } = new()
    {
        Id = "VC-INPUT-001",
        Title = "Stack allocation sized from a variable",
        Severity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "A stackalloc is sized from a value computed at runtime rather than from a constant. "
            + "If that value can be influenced by input the application does not control, an "
            + "oversized request overflows the stack and terminates the process immediately. "
            + "Unlike a heap allocation failure this cannot be caught or recovered from.",
        Remediation =
            "Cap the length before allocating, and fall back to a pooled or heap buffer above the "
            + "threshold. The usual shape is: allocate on the stack only when the size is below a "
            + "fixed limit such as 256 elements, and rent an array otherwise.",
        Pattern = PatternRule.Compile(
            """stackalloc\s+\w+\s*\[\s*(?<size>[^\]]{1,80}?)\s*\]""",
            RegexOptions.IgnoreCase),
        Languages = [SourceLanguage.CSharp],
        Ignore = (match, context) => IsBounded(match.Groups["size"].Value, context.LineFor(match)),
    };

    /// <summary>
    /// True when the allocation is already bounded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The guarded ternary is the recommended fix for this very rule and keeps the check on
    /// the same line as the allocation:
    /// <c>name.Length > 256 ? new char[name.Length] : stackalloc char[name.Length]</c>.
    /// Reporting that form tells a developer their correct fix is still a bug, which is worse
    /// than missing the case entirely.
    /// </para>
    /// <para>
    /// Matching guard keywords is not enough: the bound is often written against a local
    /// (<c>len &lt;= 128</c>) rather than against a Length property. So this compares the
    /// actual size expression used in the allocation against the comparisons on the line.
    /// </para>
    /// </remarks>
    private static bool IsBounded(string sizeExpression, string line)
    {
        var size = sizeExpression.Trim();

        if (size.Length == 0)
        {
            return true;
        }

        // A constant size is bounded by definition.
        if (size.All(char.IsAsciiDigit))
        {
            return true;
        }

        // An explicit clamp inside the size expression itself.
        if (size.Contains("Math.Min", StringComparison.OrdinalIgnoreCase)
            || size.Contains("Math.Clamp", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var escaped = Regex.Escape(size);

        return Regex.IsMatch(
            line,
            $@"{escaped}\s*(?:<=?|>=?)\s*\d+|\d+\s*(?:<=?|>=?)\s*{escaped}",
            RegexOptions.None,
            PatternRule.MatchTimeout);
    }

    /// <summary>
    /// Shell-opening a URL held in a variable.
    /// </summary>
    /// <remarks>
    /// From a real finding on an update-check "Download" link. Process.Start with shell
    /// execution hands the string to the operating system, which will happily act on
    /// <c>file:</c> and other schemes, so a value that reached the application from a remote
    /// response can launch something local rather than opening a browser.
    /// </remarks>
    private static PatternRule ShellOpenOfDynamicUrl { get; } = new()
    {
        Id = "VC-INPUT-002",
        Title = "Shell-opens a URL without validating its scheme",
        Severity = Severity.Medium,
        Category = FindingCategory.Network,
        Description =
            "The application shell-opens an address held in a variable. If that value came from "
            + "a remote source, such as an update check or an API response, the operating system "
            + "will act on whatever scheme it carries. A file: or ms-: URL then launches something "
            + "local instead of opening a web page.",
        Remediation =
            "Parse the value with Uri.TryCreate and proceed only when the scheme is https, and "
            + "ideally only when the host is one you expect. Validate before launching, not after.",
        Pattern = PatternRule.Compile(
            """Process\.Start\s*\(\s*(?:new\s+ProcessStartInfo\s*\(\s*)?\w*(?:url|uri|link|address|href)\w*""",
            RegexOptions.IgnoreCase),
        Languages = [SourceLanguage.CSharp],
        Ignore = (match, context) => Heuristics.PrecededBy(context, match.Index, SchemeValidation),
    };

    /// <summary>
    /// Throwing numeric conversion applied to parsed content.
    /// </summary>
    /// <remarks>
    /// Scoped narrowly to conversions applied directly to a field or element pulled out of
    /// parsed data, which is where malformed input actually lands. A bare Parse on a local is
    /// far too common to report.
    /// </remarks>
    private static PatternRule UnguardedNumericParse { get; } = new()
    {
        Id = "VC-INPUT-003",
        Title = "Throwing numeric conversion applied to external data",
        Severity = Severity.Low,
        Category = FindingCategory.CodeSafety,
        Description =
            "A value read out of parsed data is converted with a method that throws on malformed "
            + "input. A single unexpected field from a feed, file, or API response then raises an "
            + "exception, which typically surfaces as a crash rather than a handled error.",
        Remediation =
            "Use the TryParse form and decide explicitly what to do when the value is absent or "
            + "malformed, rather than letting the conversion throw.",
        Pattern = PatternRule.Compile(
            """
            (?:int|long|double|decimal|float)\.Parse\s*\(\s*
            \w+\s*[\[.](?:"[^"]+"|\w+)
            """,
            RegexOptions.IgnorePatternWhitespace),
        Languages = [SourceLanguage.CSharp],
        Ignore = (match, context) => Heuristics.IsInLineComment(context, match.Index),
    };
}
