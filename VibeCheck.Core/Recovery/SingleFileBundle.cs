using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace VibeCheck.Core.Recovery;

/// <summary>Kind of payload a bundle entry holds, as recorded by the .NET host.</summary>
public enum BundleFileType : byte
{
    Unknown = 0,
    Assembly = 1,
    NativeBinary = 2,
    DepsJson = 3,
    RuntimeConfigJson = 4,
    Symbols = 5,
}

/// <summary>
/// Reads .NET single-file bundles: the format produced by publishing with
/// <c>PublishSingleFile</c>, where the application's assemblies are appended to a native
/// launcher.
/// </summary>
/// <remarks>
/// <para>
/// Without this a single-file application is opaque: the launcher carries no managed metadata,
/// so a PE reader calls it a native binary and the whole application goes unanalysed.
/// </para>
/// <para>
/// Layout: an 8-byte header offset immediately followed by a fixed 32-byte signature, so
/// locating the signature locates the manifest, which then gives one entry per file.
/// </para>
/// <para>
/// Every offset and length here is attacker-controlled and range-checked against the real
/// stream length before use. Nothing is written to disk.
/// </para>
/// </remarks>
public static class SingleFileBundle
{
    /// <summary>
    /// The marker the .NET host writes into a bundled launcher. It is the SHA-256 of
    /// ".net core bundle" and is stable across every version of the format.
    /// </summary>
    private static ReadOnlySpan<byte> Signature =>
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    /// <summary>Bundles carry a whole application; anything smaller is not one.</summary>
    private const long MinimumBundleSize = 1024 * 1024;

    private const int MaxEntries = 20_000;
    private const long MaxEntryBytes = 256L * 1024 * 1024;
    private const long MaxTotalBytes = 1024L * 1024 * 1024;

    public sealed record BundleEntry(string RelativePath, byte[] Content, BundleFileType Type);

    /// <summary>True when the file is a .NET single-file bundle.</summary>
    public static bool IsBundle(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            if (new FileInfo(path).Length < MinimumBundleSize)
            {
                return false;
            }

            using var stream = File.OpenRead(path);
            return IsBundle(stream);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// True when the stream holds a .NET single-file bundle.
    /// </summary>
    /// <remarks>
    /// The stream overloads exist because a bundle does not only arrive as a file on disk. An
    /// installer carries the same launcher as one of its payloads, and reading it from there
    /// means reading it from memory: writing it out first would break the promise that nothing
    /// untrusted touches the filesystem. Seekable, so a decompressing stream has to be buffered
    /// by the caller before it gets here.
    /// </remarks>
    public static bool IsBundle(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        return stream.Length >= MinimumBundleSize && FindSignature(stream) >= 0;
    }

    /// <summary>
    /// Extracts the bundle's entries. Anything malformed is skipped with an explanation
    /// rather than aborting the read, so one bad entry does not cost the whole application.
    /// </summary>
    public static IReadOnlyList<BundleEntry> Read(
        string path,
        IList<string> warnings,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(warnings);

        using var stream = File.OpenRead(path);

        return Read(stream, warnings, cancellationToken);
    }

    /// <inheritdoc cref="Read(string, IList{string}, CancellationToken)"/>
    /// <remarks>See <see cref="IsBundle(Stream)"/> for why a stream overload exists.</remarks>
    public static IReadOnlyList<BundleEntry> Read(
        Stream stream,
        IList<string> warnings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(warnings);

        var signatureOffset = FindSignature(stream);
        if (signatureOffset < 0)
        {
            warnings.Add("No single-file bundle marker was found.");
            return [];
        }

        // The manifest offset sits in the 8 bytes immediately before the signature.
        var headerOffsetPosition = signatureOffset - sizeof(long);
        if (headerOffsetPosition < 0)
        {
            warnings.Add("Bundle marker is malformed; no manifest offset precedes it.");
            return [];
        }

        stream.Position = headerOffsetPosition;
        var offsetBytes = new byte[sizeof(long)];
        stream.ReadExactly(offsetBytes);

        var headerOffset = BinaryPrimitives.ReadInt64LittleEndian(offsetBytes);
        if (headerOffset <= 0 || headerOffset >= stream.Length)
        {
            warnings.Add("Bundle manifest offset points outside the file.");
            return [];
        }

        stream.Position = headerOffset;

        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        try
        {
            return ReadEntries(reader, stream, warnings, cancellationToken);
        }
        catch (EndOfStreamException)
        {
            warnings.Add("Bundle manifest is truncated.");
            return [];
        }
        catch (IOException)
        {
            warnings.Add("Bundle manifest could not be read.");
            return [];
        }
    }

    private static List<BundleEntry> ReadEntries(
        BinaryReader reader,
        Stream stream,
        IList<string> warnings,
        CancellationToken cancellationToken)
    {
        var majorVersion = reader.ReadUInt32();
        _ = reader.ReadUInt32(); // minor version, not load-bearing here
        var fileCount = reader.ReadInt32();

        _ = reader.ReadString(); // bundle id

        // Version 2 (.NET 5) added locations for deps.json and runtimeconfig.json plus a
        // flags word, ahead of the file table.
        if (majorVersion >= 2)
        {
            reader.ReadInt64();
            reader.ReadInt64();
            reader.ReadInt64();
            reader.ReadInt64();
            reader.ReadUInt64();
        }

        if (fileCount is <= 0 or > MaxEntries)
        {
            warnings.Add($"Bundle declares an implausible file count ({fileCount}).");
            return [];
        }

        // Version 6 (.NET 6) added per-entry compressed size, enabling EnableCompressionInSingleFile.
        var hasCompression = majorVersion >= 6;

        var entries = new List<BundleEntry>();
        long totalBytes = 0;

        for (var i = 0; i < fileCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var offset = reader.ReadInt64();
            var size = reader.ReadInt64();
            var compressedSize = hasCompression ? reader.ReadInt64() : 0;
            var type = (BundleFileType)reader.ReadByte();
            var relativePath = reader.ReadString();

            // Only managed assemblies and the manifests are useful; native payloads cannot
            // be decompiled and symbols are noise.
            if (type is not (BundleFileType.Assembly or BundleFileType.DepsJson
                or BundleFileType.RuntimeConfigJson))
            {
                continue;
            }

            if (size <= 0 || size > MaxEntryBytes)
            {
                warnings.Add($"Skipped {Safe(relativePath)}: implausible size.");
                continue;
            }

            if (totalBytes + size > MaxTotalBytes)
            {
                warnings.Add("Stopped reading the bundle at the total size limit.");
                break;
            }

            var storedLength = compressedSize > 0 ? compressedSize : size;
            if (offset < 0 || storedLength <= 0 || offset + storedLength > stream.Length)
            {
                warnings.Add($"Skipped {Safe(relativePath)}: entry lies outside the file.");
                continue;
            }

            var position = stream.Position;

            try
            {
                var content = ReadEntryContent(stream, offset, storedLength, size, compressedSize > 0);
                if (content is null)
                {
                    warnings.Add($"Skipped {Safe(relativePath)}: expanded beyond its declared size.");
                    continue;
                }

                totalBytes += content.Length;
                entries.Add(new BundleEntry(Normalise(relativePath), content, type));
            }
            catch (InvalidDataException)
            {
                warnings.Add($"Skipped {Safe(relativePath)}: corrupt compressed data.");
            }
            finally
            {
                stream.Position = position;
            }
        }

        return entries;
    }

    /// <summary>
    /// Reads one entry, inflating it when stored compressed.
    /// </summary>
    /// <remarks>
    /// The declared uncompressed size bounds the read, and the bound is enforced while
    /// inflating rather than trusted, so an entry claiming to be small cannot expand without
    /// limit.
    /// </remarks>
    private static byte[]? ReadEntryContent(
        Stream stream,
        long offset,
        long storedLength,
        long expandedSize,
        bool compressed)
    {
        stream.Position = offset;

        if (!compressed)
        {
            var raw = new byte[storedLength];
            stream.ReadExactly(raw);
            return raw;
        }

        using var window = new SubStream(stream, offset, storedLength);
        using var inflater = new DeflateStream(window, CompressionMode.Decompress);
        using var buffer = new MemoryStream();

        var chunk = new byte[81920];
        long written = 0;

        while (true)
        {
            var read = inflater.Read(chunk, 0, chunk.Length);
            if (read == 0)
            {
                break;
            }

            written += read;
            if (written > expandedSize)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>Locates the bundle marker, scanning in chunks with overlap.</summary>
    private static long FindSignature(Stream stream)
    {
        const int ChunkSize = 1024 * 1024;

        var overlap = Signature.Length - 1;
        var buffer = new byte[ChunkSize + overlap];
        var carried = 0;
        long basePosition = 0;

        stream.Position = 0;

        while (true)
        {
            var read = stream.Read(buffer, carried, ChunkSize);
            if (read == 0)
            {
                return -1;
            }

            var available = carried + read;
            var index = buffer.AsSpan(0, available).IndexOf(Signature);
            if (index >= 0)
            {
                return basePosition + index;
            }

            buffer.AsSpan(available - overlap, overlap).CopyTo(buffer);
            basePosition += available - overlap;
            carried = overlap;
        }
    }

    private static string Normalise(string path) => path.Replace('\\', '/').TrimStart('/');

    /// <summary>Renders an attacker-supplied path safely for a warning message.</summary>
    private static string Safe(string raw)
    {
        var builder = new StringBuilder(Math.Min(raw.Length, 120));

        foreach (var c in raw.AsSpan(0, Math.Min(raw.Length, 120)))
        {
            builder.Append(char.IsControl(c) ? '?' : c);
        }

        return builder.ToString();
    }
}

/// <summary>
/// A read-only window over part of another stream, so a compressed entry can be inflated
/// without copying the stored bytes out first.
/// </summary>
internal sealed class SubStream(Stream inner, long offset, long length) : Stream
{
    private long _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int index, int count)
    {
        var remaining = length - _position;
        if (remaining <= 0)
        {
            return 0;
        }

        inner.Position = offset + _position;
        var read = inner.Read(buffer, index, (int)Math.Min(count, remaining));
        _position += read;

        return read;
    }

    public override void Flush() { }

    public override long Seek(long value, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int index, int count) => throw new NotSupportedException();
}
