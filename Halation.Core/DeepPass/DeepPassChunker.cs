using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.DeepPass;

/// <summary>Third-party code a bundler inlined into one of this application's own files.</summary>
/// <param name="Name">The package, as the bundler's marker names it.</param>
/// <param name="FirstLine">First line of the region, 1-based and inclusive.</param>
/// <param name="LastLine">Last line of the region, 1-based and inclusive.</param>
/// <param name="Chars">Characters the region occupies, which is what it would cost to send.</param>
public sealed record VendoredRegion(string Name, int FirstLine, int LastLine, int Chars);

/// <summary>
/// One request's worth of a file: the lines it carries, numbered as they are in the file.
/// </summary>
/// <remarks>
/// Line numbers are the file's own throughout, never the chunk's. Everything downstream of the
/// answer resolves against this application's copy of the whole file, so a chunk that numbered
/// from one would put every quotation in the wrong place. See <see cref="EvidenceLocator"/>.
/// </remarks>
public sealed record DeepPassChunk
{
    /// <summary>The file this is part of, and why it was selected.</summary>
    public required TriagedFile Source { get; init; }

    /// <summary>1-based position in the sequence of requests covering this file.</summary>
    public required int Index { get; init; }

    /// <summary>How many requests the file takes in total.</summary>
    public required int Of { get; init; }

    public required int FirstLine { get; init; }

    public required int LastLine { get; init; }

    /// <summary>The numbered code, as it goes to the model.</summary>
    public required string NumberedCode { get; init; }

    /// <summary>Characters of the file this chunk carries, before numbering.</summary>
    public required int Chars { get; init; }

    /// <summary>
    /// Findings the deterministic pass reported inside these lines, and no others.
    /// </summary>
    /// <remarks>
    /// Bounded to the chunk on purpose. A prompt listing findings from parts of the file the
    /// model was not shown asks it to judge code it cannot see, which is an invitation to answer
    /// from the finding's title rather than from the code.
    /// </remarks>
    public IReadOnlyList<Finding> KnownFindings { get; init; } = [];

    /// <summary>Bundled third-party code left out of these lines, named so the prompt can say so.</summary>
    public IReadOnlyList<VendoredRegion> Omitted { get; init; } = [];

    public RecoveredFile File => Source.File;

    /// <summary>Whether this request carries the whole file.</summary>
    public bool IsWholeFile => Of == 1 && Omitted.Count == 0;
}

/// <summary>What splitting one file produced.</summary>
public sealed record FileSplit
{
    public required IReadOnlyList<DeepPassChunk> Chunks { get; init; }

    /// <summary>Bundled third-party regions deliberately left out of every chunk.</summary>
    public IReadOnlyList<VendoredRegion> Vendored { get; init; } = [];

    /// <summary>Characters of this file that would be sent across all its chunks.</summary>
    public int Chars => Chunks.Sum(c => c.Chars);
}

/// <summary>
/// Cuts a file into the requests that will carry it.
/// </summary>
/// <remarks>
/// <para>
/// <b>It replaces a silent truncation.</b> Everything past sixty thousand characters used to be
/// dropped with a comment appended in the prompt, so an eleven-thousand-line Electron main
/// bundle was reviewed as far as line 1,895 while the prompt still listed the rule findings
/// sitting at lines 5,276 and 9,608. The model was being asked about code it had not been given,
/// and the report said the file had been read.
/// </para>
/// <para>
/// The per-request ceiling stays where it was, because it is what keeps one call inside a local
/// model's context as well as a hosted one's. What changed is that the remainder is now sent in
/// further requests instead of being thrown away.
/// </para>
/// </remarks>
public static class DeepPassChunker
{
    /// <summary>
    /// Characters of code in one request.
    /// </summary>
    /// <remarks>
    /// Unchanged from the old truncation limit, and it is a budget rather than a guess: a 7B
    /// model served locally at a 32k context handles this plus the system prompt and its own
    /// answer, and every hosted model handles far more. Raising it would make the pass cheaper
    /// per file and would start failing on the configuration this application recommends to
    /// somebody with an 8GB card.
    /// </remarks>
    public const int MaxChunkChars = 60_000;

    /// <summary>
    /// Splits one triaged file into the requests that will carry it.
    /// </summary>
    public static FileSplit Split(TriagedFile triaged)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        var lines = triaged.File.Content.ReplaceLineEndings("\n").Split('\n');
        var vendored = VendoredRegionsIn(lines);
        var skip = new bool[lines.Length];

        foreach (var region in vendored)
        {
            for (var i = region.FirstLine - 1; i <= region.LastLine - 1; i++)
            {
                skip[i] = true;
            }
        }

        var pieces = Pieces(lines, skip);
        var chunks = new List<DeepPassChunk>(pieces.Count);

        for (var i = 0; i < pieces.Count; i++)
        {
            var piece = pieces[i];

            chunks.Add(new DeepPassChunk
            {
                Source = triaged,
                Index = i + 1,
                Of = pieces.Count,
                FirstLine = piece.FirstLine,
                LastLine = piece.LastLine,
                NumberedCode = piece.Text,
                Chars = piece.Chars,
                KnownFindings = FindingsIn(triaged.KnownFindings, piece, first: i == 0),
                Omitted = [.. vendored.Where(
                    r => r.FirstLine >= piece.FirstLine && r.FirstLine <= piece.LastLine)],
            });
        }

        return new FileSplit { Chunks = chunks, Vendored = vendored };
    }

    /// <summary>
    /// Findings the model should be told about for this piece.
    /// </summary>
    /// <remarks>
    /// A finding with no line cannot be placed, so it goes with the first request rather than
    /// with all of them: repeating it would ask every part of the file to account for it.
    /// </remarks>
    private static IReadOnlyList<Finding> FindingsIn(
        IReadOnlyList<Finding> findings, Piece piece, bool first) =>
        [.. findings.Where(f => f.Line is { } line
            ? line >= piece.FirstLine && line <= piece.LastLine
            : first)];

    /// <summary>One request's lines, before it becomes a chunk.</summary>
    private sealed record Piece(int FirstLine, int LastLine, string Text, int Chars);

    /// <summary>
    /// Walks the file, accumulating lines until the next one would not fit.
    /// </summary>
    /// <remarks>
    /// A single line longer than the whole budget is split across requests rather than dropped,
    /// because that is exactly what a minified bundle is: the renderer bundle of a real
    /// application was 1.4 million characters on 34 lines. Each part of a split line keeps the
    /// line's own number, so a quotation still resolves to the right place.
    /// </remarks>
    private static List<Piece> Pieces(string[] lines, bool[] skip)
    {
        var pieces = new List<Piece>();
        var builder = new StringBuilder();
        var chars = 0;
        var firstLine = 0;
        var lastLine = 0;

        void Flush()
        {
            if (builder.Length == 0)
            {
                return;
            }

            pieces.Add(new Piece(firstLine, lastLine, builder.ToString().TrimEnd('\n'), chars));
            builder.Clear();
            chars = 0;
            firstLine = 0;
        }

        for (var i = 0; i < lines.Length; i++)
        {
            if (skip[i])
            {
                continue;
            }

            var number = i + 1;
            var line = lines[i];

            foreach (var part in Wrap(line))
            {
                if (chars > 0 && chars + part.Length + 1 > MaxChunkChars)
                {
                    Flush();
                }

                if (firstLine == 0)
                {
                    firstLine = number;
                }

                lastLine = number;
                chars += part.Length + 1;

                builder.Append(number.ToString(CultureInfo.InvariantCulture).PadLeft(4))
                       .Append("| ")
                       .Append(part)
                       .Append('\n');
            }
        }

        Flush();

        return pieces;
    }

    /// <summary>One line, in pieces no larger than a request can carry.</summary>
    private static IEnumerable<string> Wrap(string line)
    {
        if (line.Length <= MaxChunkChars)
        {
            yield return line;
            yield break;
        }

        for (var start = 0; start < line.Length; start += MaxChunkChars)
        {
            yield return line.Substring(start, Math.Min(MaxChunkChars, line.Length - start));
        }
    }

    /// <summary>
    /// The bundled third-party regions in a file, paired marker to marker.
    /// </summary>
    /// <remarks>
    /// Nested markers are counted rather than assumed away, since a bundled package that itself
    /// requires another produces a region inside a region. A region that is never closed is
    /// treated as no region at all: excluding the rest of the file on the strength of one
    /// unmatched comment would drop the reader's own code and say it was somebody else's.
    /// </remarks>
    public static IReadOnlyList<VendoredRegion> VendoredRegionsIn(IReadOnlyList<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        var regions = new List<VendoredRegion>();

        for (var i = 0; i < lines.Count; i++)
        {
            if (BundleMarkers.PackageOpenedBy(lines[i]) is not { } name)
            {
                continue;
            }

            var depth = 1;
            var end = -1;

            for (var j = i + 1; j < lines.Count; j++)
            {
                if (BundleMarkers.OpensAnyRegion(lines[j]))
                {
                    depth++;
                }
                else if (BundleMarkers.ClosesRegion(lines[j]) && --depth == 0)
                {
                    end = j;
                    break;
                }
            }

            if (end < 0)
            {
                continue;
            }

            var chars = 0;

            for (var j = i; j <= end; j++)
            {
                chars += lines[j].Length + 1;
            }

            regions.Add(new VendoredRegion(name, i + 1, end + 1, chars));
            i = end;
        }

        return regions;
    }
}
