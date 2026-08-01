using System.Text;

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
