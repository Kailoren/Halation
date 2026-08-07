using System.Text.RegularExpressions;

namespace VibeCheck.Core.DeepPass;

/// <summary>
/// Turns a model's claim about where something is into a quotation taken from the file itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>The model is asked to point, not to transcribe.</b> Evidence used to be whatever string the
/// model put in an <c>evidence</c> field, printed to the reader inside a code fence as though it
/// were a line out of their own file. Measured against a real project, a local model put its own
/// prose in that field nine times out of twenty-four: sentences describing the file rather than
/// anything appearing in it. A quotation the reader cannot find is worse than no quotation,
/// because the fence is what invites them to stop checking.
/// </para>
/// <para>
/// So the text now comes from the copy of the file this application already holds, and the model
/// only supplies a line number. A fabricated quotation stops being something to detect and starts
/// being something that cannot be constructed.
/// </para>
/// <para>
/// <b>A wrong line number is deliberately not treated as a failure.</b> If the model cites a line
/// that does not support its claim, quoting that line is exactly what lets a reader dismiss the
/// finding in seconds. The alternative, suppressing anything whose quotation looks unrelated,
/// would hide the model's mistakes rather than expose them.
/// </para>
/// </remarks>
public static class EvidenceLocator
{
    /// <summary>How far either side of a cited line to look for the model's own wording.</summary>
    /// <remarks>
    /// Small on purpose. A model that is one or two lines out is pointing at the right code and
    /// has miscounted; one that is fifty lines out is not pointing at anything, and widening the
    /// search until something matches would manufacture agreement.
    /// </remarks>
    private const int NearbyLines = 3;

    /// <summary>Longest quotation kept, before <see cref="Rules.Redaction"/> trims it further.</summary>
    private const int MaxQuotedLines = 3;

    /// <summary>
    /// A quotation from the file, and the line it came from.
    /// </summary>
    /// <param name="Evidence">Text taken from the file, or null when nothing could be located.</param>
    /// <param name="Line">The 1-based line the quotation came from, or null.</param>
    public readonly record struct Located(string? Evidence, int? Line)
    {
        /// <summary>Whether the claim could be tied to anything in the file at all.</summary>
        public bool Found => Evidence is not null;
    }

    /// <summary>
    /// Finds what the model was pointing at, preferring the line it named and falling back to
    /// searching for its own wording.
    /// </summary>
    /// <remarks>
    /// The fallback exists because the line number is only as reliable as the model's counting,
    /// and a model that quoted real code while miscounting its position has still shown the
    /// reader something true. Both routes end at text this application read out of the file, so
    /// neither can produce a quotation that is not there.
    /// </remarks>
    public static Located Locate(string? fileContent, int? claimedLine, string? claimedText)
    {
        if (string.IsNullOrEmpty(fileContent))
        {
            return default;
        }

        var lines = fileContent.ReplaceLineEndings("\n").Split('\n');

        if (claimedLine is { } line && line >= 1 && line <= lines.Length)
        {
            var quoted = Quote(lines, line - 1);

            if (quoted is not null)
            {
                return new Located(quoted, line);
            }
        }

        // The model named no usable line, or named a blank one. Its own wording is the only
        // remaining handle, and it is only usable if it turns out to be real.
        var index = IndexOfClaim(lines, claimedText, claimedLine);

        return index >= 0
            ? new Located(Quote(lines, index), index + 1)
            : default;
    }

    /// <summary>
    /// The cited line plus as much of what follows as is needed to make it a readable statement.
    /// </summary>
    /// <remarks>
    /// One line is often not a whole thought: a call broken across several lines, or an
    /// <c>if</c> whose condition sits under it, reads as a fragment on its own and invites the
    /// reader to conclude the finding is nonsense when it is only clipped. Continuation is judged
    /// by unbalanced brackets rather than by counting lines, so ordinary statements stay one line.
    /// </remarks>
    private static string? Quote(string[] lines, int index)
    {
        if (string.IsNullOrWhiteSpace(lines[index]))
        {
            return null;
        }

        // A line carrying no content of its own is as much use to a reader as no quotation at
        // all, which is the failure this whole class exists to prevent. Both kinds showed up
        // immediately on a real run: findings whose entire evidence was "{", and findings whose
        // evidence was "/// </summary>".
        //
        // The two are walked in opposite directions on purpose. A brace belongs to the statement
        // above it; a documentation comment describes the member below it. Walking a doc comment
        // backwards only goes further into the comment.
        for (var step = 0; step < NearbyLines && index > 0 && IsPunctuationOnly(lines[index]); step++)
        {
            index--;
        }

        for (var step = 0;
             step < NearbyLines && index < lines.Length - 1 && IsCommentScaffolding(lines[index]);
             step++)
        {
            index++;
        }

        if (string.IsNullOrWhiteSpace(lines[index])
            || IsPunctuationOnly(lines[index])
            || IsCommentScaffolding(lines[index]))
        {
            return null;
        }

        var taken = new List<string> { lines[index] };
        var depth = Balance(lines[index]);

        for (var i = index + 1; depth > 0 && taken.Count < MaxQuotedLines && i < lines.Length; i++)
        {
            taken.Add(lines[i]);
            depth += Balance(lines[i]);
        }

        return string.Join("\n", taken).TrimEnd();
    }

    /// <summary>
    /// Whether a line carries no code of its own, only the punctuation around it.
    /// </summary>
    private static bool IsPunctuationOnly(string line)
    {
        var trimmed = line.Trim();

        return trimmed.Length > 0
            && trimmed.All(c => c is '{' or '}' or '(' or ')' or '[' or ']' or ';' or ',');
    }

    /// <summary>
    /// A documentation tag and nothing else, such as <c>/// &lt;summary&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Only the scaffolding. A comment with words in it is quotable evidence and sometimes the
    /// best there is, since a comment is where an author says why something that looks alarming
    /// is deliberate. What carries nothing is the markup around it.
    /// </remarks>
    private static bool IsCommentScaffolding(string line) =>
        DocScaffolding.IsMatch(line.Trim());

    private static readonly Regex DocScaffolding = new(
        @"^(///|//|\*)\s*</?[A-Za-z][A-Za-z0-9]*(\s+[^<>]*)?/?>\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>How far the brackets on one line are left open.</summary>
    private static int Balance(string line)
    {
        var depth = 0;

        foreach (var c in line)
        {
            if (c is '(' or '[') depth++;
            else if (c is ')' or ']') depth--;
        }

        return depth;
    }

    /// <summary>
    /// Looks for the model's own wording in the file, nearest the line it named first.
    /// </summary>
    /// <remarks>
    /// Comparison ignores whitespace, because a model reproducing a line rarely reproduces its
    /// indentation, and that is not a difference worth failing on. It does not ignore anything
    /// else: a paraphrase is supposed to fail here, since that is the whole point.
    /// </remarks>
    private static int IndexOfClaim(string[] lines, string? claimedText, int? claimedLine)
    {
        var needle = Squash(claimedText?.ReplaceLineEndings("\n").Split('\n').FirstOrDefault(
            l => !string.IsNullOrWhiteSpace(l)));

        // Too short to identify anything. A handful of characters matches half the file and the
        // match would be an accident rather than a location.
        if (needle.Length < 12)
        {
            return -1;
        }

        // Nearest the claim first, so a model that miscounted by a line lands on its own code
        // rather than on a similar line elsewhere in the file.
        if (claimedLine is { } line && line >= 1 && line <= lines.Length)
        {
            for (var offset = 1; offset <= NearbyLines; offset++)
            {
                foreach (var candidate in new[] { line - 1 - offset, line - 1 + offset })
                {
                    if (candidate >= 0 && candidate < lines.Length && Matches(lines[candidate], needle))
                    {
                        return candidate;
                    }
                }
            }
        }

        for (var i = 0; i < lines.Length; i++)
        {
            if (Matches(lines[i], needle))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool Matches(string line, string needle) =>
        Squash(line) is { Length: > 0 } squashed
        && (squashed.Contains(needle, StringComparison.Ordinal)
            || needle.Contains(squashed, StringComparison.Ordinal));

    private static string Squash(string? text) =>
        string.IsNullOrEmpty(text)
            ? ""
            : string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
}
