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
    /// <inheritdoc cref="SecretRules.All"/>
    public static IReadOnlyList<IRule> All =>
    [
        UnboundedStackAllocation,
        ShellOpenOfDynamicUrl,
        UnguardedNumericParse,
    ];

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
            """stackalloc\s+\w+\s*\[\s*(?![\d\s]+\])""",
            RegexOptions.IgnoreCase),
        Languages = [SourceLanguage.CSharp],
    };

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
