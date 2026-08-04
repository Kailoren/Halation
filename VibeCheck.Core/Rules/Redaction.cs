using System.Text;
using System.Text.RegularExpressions;

namespace VibeCheck.Core.Rules;

/// <summary>
/// Masks sensitive values before they reach a report.
/// </summary>
/// <remarks>
/// A scanner that quotes a live key in full has disclosed it again, and reports get pasted into
/// issue trackers. Redacted where evidence is produced rather than where it is shown, so every
/// rendering path inherits it. Enough of the prefix survives to tell which key to rotate.
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
    /// Everything the deep pass returns is derived from the scanned application's own source,
    /// so a prompt injection reaches it. A title carrying two newlines and a <c>##</c> forged a
    /// whole verdict section reading "safe to install" in an exported report. Markdown structure
    /// is decided at the start of a line, so the line breaks are what goes.
    /// </remarks>
    /// <summary>
    /// Ceiling for a paragraph meant to be read, as opposed to a label.
    /// </summary>
    /// <remarks>
    /// The old default of 400 was a label's budget applied to prose, and it cut every deep pass
    /// explanation off mid-sentence: the reader was shown a description that stopped at "if the
    /// update server were ever compromised, or if someone were able to intercept the che…". A
    /// bound is still wanted, because this text comes back from a model that has just read a
    /// file the scanner assumes is hostile, but the bound has to be large enough to hold the
    /// answer it was asked for.
    /// </remarks>
    public const int MaxProse = 2000;

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
    /// The rest of this class protects secrets found <i>in</i> a scanned application; this one
    /// protects the reader's own. Two paths carry text this codebase did not write into an
    /// exportable report: an SDK exception, and whatever a local Claude Code prints on failure.
    /// Neither is known to carry a credential, but the cost of being wrong is a billing key in a
    /// public issue tracker. Applied where messages are built, so a later one inherits it.
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
