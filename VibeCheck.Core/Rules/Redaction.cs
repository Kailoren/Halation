using System.Text;
using System.Text.RegularExpressions;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Masks sensitive values before they reach a report.
/// </summary>
/// <remarks>
/// A scanner that quotes a live API key in full has disclosed it again. Reports get pasted
/// into issue trackers, chat, and screenshots, so evidence is redacted at the point it is
/// produced rather than at the point it is displayed. Every rendering path then inherits the
/// protection instead of each one having to remember.
/// <para>
/// Enough of the prefix survives for the developer to identify which key it is, since
/// "rotate the key" is useless advice if they cannot tell which of several it refers to.
/// </para>
/// </remarks>
public static class Redaction
{
    /// <summary>Characters of a secret left visible so it can be identified.</summary>
    private const int VisiblePrefix = 4;

    /// <summary>Cap on evidence length, so a minified bundle cannot dump a whole line.</summary>
    private const int MaxEvidenceLength = 200;

    /// <summary>Replaces all but a short prefix of a secret with asterisks.</summary>
    public static string MaskSecret(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        if (secret.Length <= VisiblePrefix)
        {
            return new string('*', secret.Length);
        }

        var hidden = Math.Min(secret.Length - VisiblePrefix, 16);
        return string.Concat(secret.AsSpan(0, VisiblePrefix), new string('*', hidden));
    }

    /// <summary>
    /// Renders a source line as report evidence, masking the matched secret within it and
    /// trimming the surrounding context.
    /// </summary>
    public static string BuildEvidence(string line, string? secret = null)
    {
        ArgumentNullException.ThrowIfNull(line);

        var text = line.Trim();

        if (!string.IsNullOrEmpty(secret) && text.Contains(secret, StringComparison.Ordinal))
        {
            text = text.Replace(secret, MaskSecret(secret), StringComparison.Ordinal);
        }

        return Truncate(Sanitise(text));
    }

    /// <summary>
    /// Flattens text that came from a language model into a single line of plain prose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The deep pass reads an application's own source and returns text derived from it, so
    /// every field it fills is attacker-controlled by way of a prompt injection. The Markdown
    /// export puts a finding's title into a heading, and a title carrying two newlines and a
    /// <c>##</c> was enough to forge a whole verdict section reading "no known issues found,
    /// safe to install" in a document the reader saves and forwards. Nothing was wrong with the
    /// report on screen; the artifact people pass around said the opposite of what was found.
    /// </para>
    /// <para>
    /// Line breaks are what carry the attack, because Markdown structure is decided at the
    /// start of a line, so they are what goes. The composed description keeps its own paragraph
    /// breaks: those are added by this codebase around the flattened pieces, and a caller
    /// cannot be tricked into arranging its own text.
    /// </para>
    /// </remarks>
    public static string? Flatten(string? text, int max = 400)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var flattened = Sanitise(text);

        // Sanitise turns every control character into a space, so runs of them are what a
        // stripped newline leaves behind.
        while (flattened.Contains("  ", StringComparison.Ordinal))
        {
            flattened = flattened.Replace("  ", " ", StringComparison.Ordinal);
        }

        flattened = Scrub(flattened.Trim());

        return flattened.Length <= max ? flattened : string.Concat(flattened.AsSpan(0, max), "…");
    }

    /// <summary>
    /// Removes anything shaped like the reader's own Anthropic key from a message they may
    /// publish.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rest of this class protects secrets found <i>in</i> a scanned application. This one
    /// protects the reader's own credential, and it exists because two paths carry text this
    /// codebase did not write into a report the reader can export: an exception message from
    /// the Anthropic SDK, and whatever a locally installed Claude Code prints when it fails.
    /// Neither is known to include a credential and neither is expected to. The point is that
    /// the cost of being wrong is somebody's billing key pasted into a public issue tracker,
    /// which is a poor thing to be shipped by a scanner whose own report warns other people
    /// about leaked keys.
    /// </para>
    /// <para>
    /// Applied where limitations and errors are constructed rather than where they are shown,
    /// so a message added later cannot forget to ask for it.
    /// </para>
    /// </remarks>
    public static string Scrub(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return AnthropicKey.Replace(text, "sk-ant-[redacted]");
    }

    /// <summary>
    /// Both live prefixes, and enough trailing characters to be a key rather than a mention of
    /// one. Deliberately not a general "anything long and random" pattern: this runs over
    /// diagnostic text whose whole value is being readable, and a broad pattern would eat the
    /// file paths and model names that make a failure explicable.
    /// </summary>
    private static readonly Regex AnthropicKey =
        PatternRule.Compile(@"sk-ant-[A-Za-z0-9_\-]{6,}", RegexOptions.IgnoreCase);

    /// <summary>
    /// Strips control characters from scanned content.
    /// </summary>
    /// <remarks>
    /// The text being quoted comes from a file the scanner assumes is hostile. A newline or
    /// ANSI escape inside it would let a crafted input forge extra lines in the Markdown
    /// export or the terminal, so an attacker could fabricate findings or hide real ones.
    /// </remarks>
    private static string Sanitise(string text)
    {
        var builder = new StringBuilder(text.Length);

        foreach (var c in text)
        {
            builder.Append(char.IsControl(c) ? ' ' : c);
        }

        return builder.ToString();
    }

    private static string Truncate(string text) =>
        text.Length <= MaxEvidenceLength
            ? text
            : string.Concat(text.AsSpan(0, MaxEvidenceLength), "…");
}
