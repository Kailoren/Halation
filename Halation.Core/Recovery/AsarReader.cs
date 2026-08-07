using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace Halation.Core.Recovery;

/// <summary>
/// Reads Electron <c>.asar</c> containers.
/// </summary>
/// <remarks>
/// <para>
/// An asar is a Chromium Pickle header followed by concatenated file bodies:
/// <c>[uint32 = 4][uint32 headerSize][uint32 payloadSize][uint32 jsonLength][json][data...]</c>,
/// where each entry in the JSON directory carries a byte offset into the data region. File
/// bodies begin at <c>8 + headerSize</c>.
/// </para>
/// <para>
/// Implemented directly rather than by shelling out to the npm <c>asar</c> tool, so the
/// scanner stays self-contained and runs offline with no Node runtime present. Every offset
/// and length in the header is attacker-controlled, so all of them are range-checked against
/// the real file length before use.
/// </para>
/// </remarks>
public static class AsarReader
{
    private const int MinimumHeaderBytes = 16;

    public sealed record AsarEntry(string Path, byte[] Content);

    /// <summary>
    /// Enumerates the files inside an asar. Entries that are unpacked, out of range, or
    /// oversized are skipped with an explanation appended to <paramref name="warnings"/>.
    /// </summary>
    public static IReadOnlyList<AsarEntry> Read(
        Stream stream,
        IList<string> warnings,
        ArchiveLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(warnings);

        limits ??= ArchiveLimits.Default;

        var header = ReadHeader(stream, warnings, out var dataOffset);
        if (header is null)
        {
            return [];
        }

        var results = new List<AsarEntry>();
        long totalBytes = 0;

        foreach (var (path, node) in Flatten(header.Value, warnings, limits.MaxEntries))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (node.Unpacked)
            {
                // The body lives beside the archive in app.asar.unpacked/. The directory
                // walker picks those up separately; noting it keeps coverage honest.
                warnings.Add($"{path} is stored unpacked outside the archive.");
                continue;
            }

            if (node.Size > limits.MaxFileBytes)
            {
                warnings.Add($"Skipped {path}: exceeds the per-file size limit.");
                continue;
            }

            if (totalBytes + node.Size > limits.MaxTotalBytes)
            {
                warnings.Add("Stopped reading the archive at the total size limit.");
                break;
            }

            var start = dataOffset + node.Offset;
            if (start < 0 || node.Size < 0 || start + node.Size > stream.Length)
            {
                warnings.Add($"Skipped {path}: header offset points outside the file.");
                continue;
            }

            var buffer = new byte[node.Size];
            stream.Position = start;
            stream.ReadExactly(buffer);

            totalBytes += buffer.Length;
            results.Add(new AsarEntry(path, buffer));
        }

        return results;
    }

    /// <summary>Parses and validates the header, returning the JSON directory root.</summary>
    private static JsonElement? ReadHeader(Stream stream, IList<string> warnings, out long dataOffset)
    {
        dataOffset = 0;

        if (stream.Length < MinimumHeaderBytes)
        {
            warnings.Add("File is too small to be an asar archive.");
            return null;
        }

        var prefix = new byte[MinimumHeaderBytes];
        stream.Position = 0;
        stream.ReadExactly(prefix);

        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(4));
        var jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(12));

        // Reject a header that claims to be larger than the file, before allocating for it.
        if (jsonLength == 0
            || jsonLength > 64 * 1024 * 1024
            || MinimumHeaderBytes + jsonLength > stream.Length)
        {
            warnings.Add("Asar header length is implausible; archive is corrupt or not an asar.");
            return null;
        }

        var json = new byte[jsonLength];
        stream.Position = MinimumHeaderBytes;
        stream.ReadExactly(json);

        dataOffset = 8L + headerSize;
        if (dataOffset <= 0 || dataOffset > stream.Length)
        {
            warnings.Add("Asar data section starts outside the file; archive is corrupt.");
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            warnings.Add("Asar header is not valid JSON.");
            return null;
        }
    }

    private readonly record struct Node(long Offset, long Size, bool Unpacked);

    /// <summary>
    /// Walks the nested <c>files</c> directory into flat paths, bounded in both breadth and
    /// depth so a crafted header cannot exhaust memory or the stack.
    /// </summary>
    private static IEnumerable<(string Path, Node Node)> Flatten(
        JsonElement root,
        IList<string> warnings,
        int maxEntries)
    {
        var results = new List<(string, Node)>();
        var pending = new Stack<(JsonElement Element, string Prefix, int Depth)>();
        pending.Push((root, string.Empty, 0));

        while (pending.Count > 0)
        {
            var (element, prefix, depth) = pending.Pop();

            if (depth > 64)
            {
                warnings.Add($"Stopped at {prefix}: directory nesting is implausibly deep.");
                continue;
            }

            if (!element.TryGetProperty("files", out var files)
                || files.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var child in files.EnumerateObject())
            {
                if (results.Count >= maxEntries)
                {
                    warnings.Add("Archive contains more entries than the scanner will read.");
                    return results;
                }

                // Header keys are attacker-controlled and end up in report output, so a
                // traversal segment is dropped rather than rendered as a finding location.
                if (child.Name.Contains('/') || child.Name.Contains('\\') || child.Name is ".." or ".")
                {
                    warnings.Add("Skipped an archive entry with an unsafe name.");
                    continue;
                }

                var path = prefix.Length == 0 ? child.Name : $"{prefix}/{child.Name}";

                if (child.Value.TryGetProperty("files", out _))
                {
                    pending.Push((child.Value, path, depth + 1));
                    continue;
                }

                if (TryReadNode(child.Value, out var node))
                {
                    results.Add((path, node));
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Reads one file node. The <c>offset</c> field is a decimal string in the asar format
    /// because it can exceed the range JavaScript integers represent exactly.
    /// </summary>
    private static bool TryReadNode(JsonElement element, out Node node)
    {
        node = default;

        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty("size", out var sizeElement)
            || !sizeElement.TryGetInt64(out var size))
        {
            return false;
        }

        var unpacked = element.TryGetProperty("unpacked", out var unpackedElement)
                       && unpackedElement.ValueKind == JsonValueKind.True;

        long offset = 0;
        if (!unpacked)
        {
            if (!element.TryGetProperty("offset", out var offsetElement)
                || !long.TryParse(
                    offsetElement.ValueKind == JsonValueKind.String
                        ? offsetElement.GetString()
                        : offsetElement.ToString(),
                    out offset))
            {
                return false;
            }
        }

        node = new Node(offset, size, unpacked);
        return true;
    }

    /// <summary>Convenience overload for a path on disk.</summary>
    public static IReadOnlyList<AsarEntry> Read(
        string path,
        IList<string> warnings,
        ArchiveLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        using var stream = File.OpenRead(path);
        return Read(stream, warnings, limits, cancellationToken);
    }

    /// <summary>Decodes an entry as text, or null when it is binary.</summary>
    public static string? AsText(AsarEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return SafeArchive.DecodeText(entry.Content);
    }

    internal static Encoding Utf8NoBom { get; } = new UTF8Encoding(false, false);
}
