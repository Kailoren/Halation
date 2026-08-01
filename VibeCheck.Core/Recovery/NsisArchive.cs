using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Text;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Reads the payload out of an NSIS installer without running it.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of what people actually download. An installer is a native PE, so the
/// scanner classified it as unreadable and honestly refused - while the real application sat
/// compressed a few layers inside. For an Electron app that is the difference between zero
/// coverage and reading the entire source.
/// </para>
/// <para>
/// Deliberately, this does not interpret the install script. NSIS has no file table: names
/// come from opcodes in a bytecode section, and reproducing that interpreter would be a large
/// amount of code with a large amount of attack surface. The data section is a flat sequence
/// of length-prefixed blobs, so walking it recovers every payload without any of that. The
/// cost is that blobs arrive unnamed, which is acceptable because the next stage identifies
/// them by content anyway.
/// </para>
/// <para>
/// Nothing is written to disk, matching <see cref="SafeArchive"/>. A stored blob is exposed
/// as a window onto the original file rather than copied into memory, because the payload is
/// routinely 100 MB or more and buffering it would cost more than the whole scan.
/// </para>
/// </remarks>
public static class NsisArchive
{
    /// <summary>0xDEADBEEF followed by "NullsoftInst", at offset 4 of the first header.</summary>
    private static readonly byte[] Signature =
        [0xEF, 0xBE, 0xAD, 0xDE, .. "NullsoftInst"u8];

    /// <summary>Bytes from the first header to the start of the data section.</summary>
    /// <remarks>flags(4) + signature(16) + header size(4) + archive size(4).</remarks>
    private const int FirstHeaderLength = 28;

    /// <summary>
    /// How far past the PE overlay to look for the signature. The overlay start is the
    /// expected position, but build tooling sometimes pads, so allow a small window rather
    /// than scanning the whole file for a four-byte pattern that could occur by chance.
    /// </summary>
    private const int SignatureSearchWindow = 128 * 1024;

    /// <summary>Refuses to inflate a blob past this, so a crafted installer cannot exhaust memory.</summary>
    private const long MaxInflatedBlobBytes = 256L * 1024 * 1024;

    /// <summary>One payload in the data section.</summary>
    public sealed record Blob
    {
        /// <summary>Position of the blob's contents, past its length prefix.</summary>
        public required long Offset { get; init; }

        /// <summary>Bytes occupied in the installer, compressed if <see cref="IsCompressed"/>.</summary>
        public required long StoredLength { get; init; }

        public required bool IsCompressed { get; init; }
    }

    /// <summary>
    /// Cheap test used during detection: is there an NSIS archive attached to this PE.
    /// </summary>
    public static bool IsInstaller(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        try
        {
            using var stream = File.OpenRead(path);
            return FindFirstHeader(stream) is not null;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Locates the first header, or null when the file carries no NSIS archive.
    /// </summary>
    private static long? FindFirstHeader(Stream stream)
    {
        var start = OverlayOffset(stream);
        if (start is null)
        {
            return null;
        }

        var length = (int)Math.Min(SignatureSearchWindow, stream.Length - start.Value);
        if (length < FirstHeaderLength)
        {
            return null;
        }

        var window = new byte[length];
        stream.Position = start.Value;
        var read = stream.ReadAtLeast(window, length, throwOnEndOfStream: false);

        var index = window.AsSpan(0, read).IndexOf(Signature);

        // The signature sits at offset 4 of the first header, past the flags word, so a match
        // in the first four bytes of the window would put the header before the overlay.
        return index >= 4 ? start.Value + index - 4 : null;
    }

    /// <summary>
    /// Where the PE's own content ends and appended data begins.
    /// </summary>
    private static long? OverlayOffset(Stream stream)
    {
        try
        {
            stream.Position = 0;
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);

            long end = 0;
            foreach (var section in reader.PEHeaders.SectionHeaders)
            {
                end = Math.Max(end, (long)section.PointerToRawData + section.SizeOfRawData);
            }

            return end > 0 && end < stream.Length ? end : null;
        }
        catch (BadImageFormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Enumerates the payloads in <paramref name="path"/>, or an empty list when the archive
    /// cannot be walked. <paramref name="warnings"/> records why, so the report can say that
    /// an installer was recognised but not read rather than implying it held nothing.
    /// </summary>
    public static IReadOnlyList<Blob> ReadBlobs(
        string path,
        IList<string> warnings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(warnings);

        using var stream = File.OpenRead(path);

        if (FindFirstHeader(stream) is not { } firstHeader)
        {
            return [];
        }

        stream.Position = firstHeader;
        var head = new byte[FirstHeaderLength];

        if (stream.ReadAtLeast(head, FirstHeaderLength, throwOnEndOfStream: false) < FirstHeaderLength)
        {
            warnings.Add("The installer's header is truncated.");
            return [];
        }

        var headerSize = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(20));
        var archiveSize = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(24));

        if (headerSize <= 0 || archiveSize <= FirstHeaderLength)
        {
            warnings.Add("The installer's header is malformed.");
            return [];
        }

        // The archive ends before the file does: installers carry an Authenticode signature
        // after it. Walking to end-of-file instead reads the certificate as a payload.
        var end = Math.Min(firstHeader + archiveSize, stream.Length);
        var position = firstHeader + FirstHeaderLength;

        // The first blob is the header block, and it declares its own inflated size. Checking
        // it round-trips is both a correctness check and the discriminator for solid archives,
        // where the whole data section is one stream and per-blob walking does not apply.
        if (ReadBlobHeader(stream, position, end) is not { } headerBlob)
        {
            warnings.Add("The installer's payload table could not be read.");
            return [];
        }

        if (Inflate(stream, headerBlob, headerSize, cancellationToken) is not { } inflated
            || inflated != headerSize)
        {
            warnings.Add(
                "This installer uses a compression mode VibeCheck cannot read (its payload is "
                + "one solid stream, or a codec other than deflate). Nothing inside it was "
                + "examined.");
            return [];
        }

        position = headerBlob.Offset + headerBlob.StoredLength;

        var blobs = new List<Blob>();

        while (position < end)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (ReadBlobHeader(stream, position, end) is not { } blob)
            {
                // Trailing bytes are expected: NSIS writes a CRC word after the last payload.
                break;
            }

            blobs.Add(blob);
            position = blob.Offset + blob.StoredLength;

            if (blobs.Count > 10_000)
            {
                warnings.Add("The installer declares more payloads than are plausible; stopped.");
                break;
            }
        }

        return blobs;
    }

    /// <summary>
    /// Reads a blob's length prefix. The high bit means deflate-compressed; the remaining 31
    /// bits are the stored length.
    /// </summary>
    private static Blob? ReadBlobHeader(Stream stream, long position, long end)
    {
        if (position + 4 > end)
        {
            return null;
        }

        stream.Position = position;
        var prefix = new byte[4];

        if (stream.ReadAtLeast(prefix, 4, throwOnEndOfStream: false) < 4)
        {
            return null;
        }

        var raw = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        var compressed = (raw & 0x8000_0000) != 0;
        long stored = raw & 0x7FFF_FFFF;

        // A length running past the archive means this is not a blob header at all - most
        // often the trailing CRC read as though it were one.
        return stored <= 0 || position + 4 + stored > end
            ? null
            : new Blob
            {
                Offset = position + 4,
                StoredLength = stored,
                IsCompressed = compressed,
            };
    }

    /// <summary>
    /// Inflates a blob and returns how many bytes it produced, discarding them. Used to
    /// validate the header block without holding it.
    /// </summary>
    private static long? Inflate(
        Stream stream,
        Blob blob,
        long limit,
        CancellationToken cancellationToken)
    {
        try
        {
            using var payload = Open(stream, blob, leaveOpen: true);
            var chunk = new byte[81920];
            long total = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var read = payload.Read(chunk, 0, chunk.Length);
                if (read == 0)
                {
                    break;
                }

                total += read;

                // Stop the moment it exceeds what was declared. A header block that keeps
                // producing data is either not deflate or is deliberately malformed.
                if (total > limit)
                {
                    return total;
                }
            }

            return total;
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Opens a blob's contents. A stored blob becomes a seekable window onto the installer,
    /// with no copy; a compressed one is inflated on the fly.
    /// </summary>
    /// <remarks>
    /// Seekability matters: the payload is usually a 7z archive, whose footer must be read
    /// before its entries, so a forward-only stream cannot be used to open one.
    /// </remarks>
    public static Stream Open(Stream installer, Blob blob, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(installer);
        ArgumentNullException.ThrowIfNull(blob);

        var window = new WindowStream(installer, blob.Offset, blob.StoredLength, leaveOpen);

        return blob.IsCompressed
            ? new DeflateStream(window, CompressionMode.Decompress, leaveOpen: false)
            : window;
    }

    /// <summary>
    /// Reads a blob fully into memory, up to <paramref name="limit"/>, returning null if it
    /// runs past that.
    /// </summary>
    public static byte[]? ReadFully(
        Stream installer,
        Blob blob,
        long limit,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(installer);
        ArgumentNullException.ThrowIfNull(blob);

        if (limit > MaxInflatedBlobBytes)
        {
            limit = MaxInflatedBlobBytes;
        }

        try
        {
            using var payload = Open(installer, blob, leaveOpen: true);
            using var buffer = new MemoryStream();

            var chunk = new byte[81920];
            long written = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var read = payload.Read(chunk, 0, chunk.Length);
                if (read == 0)
                {
                    break;
                }

                written += read;

                // Enforced during decompression rather than from the declared length, which
                // an attacker writes.
                if (written > limit)
                {
                    return null;
                }

                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>Identifies a blob by its leading bytes, since NSIS gives us no names.</summary>
    public static string? SniffFormat(ReadOnlySpan<byte> head) => head switch
    {
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, ..] => "7z",
        [0x50, 0x4B, 0x03 or 0x05, 0x04 or 0x06, ..] => "zip",
        [0x04, 0x00, 0x00, 0x00, ..] => "asar",
        [0x4D, 0x5A, ..] => "pe",
        _ => null,
    };

    /// <summary>
    /// A seekable, read-only view of part of another stream.
    /// </summary>
    /// <remarks>
    /// Not shared with <see cref="SingleFileBundle"/>'s equivalent, which is deliberately
    /// forward-only. This one has to seek, and widening that one would give the bundle reader
    /// a capability it is safer without.
    /// </remarks>
    private sealed class WindowStream(Stream inner, long offset, long length, bool leaveOpen)
        : Stream
    {
        private long _position;

        public override bool CanRead => true;

        public override bool CanSeek => inner.CanSeek;

        public override bool CanWrite => false;

        public override long Length => length;

        public override long Position
        {
            get => _position;
            set => _position = Math.Clamp(value, 0, length);
        }

        public override int Read(byte[] buffer, int index, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);

            var remaining = length - _position;
            if (remaining <= 0)
            {
                return 0;
            }

            // Seek every read: the underlying stream is shared with whatever else is walking
            // the installer, so its position cannot be assumed to be ours.
            inner.Position = offset + _position;

            var read = inner.Read(buffer, index, (int)Math.Min(count, remaining));
            _position += read;

            return read;
        }

        public override long Seek(long value, SeekOrigin origin)
        {
            var target = origin switch
            {
                SeekOrigin.Begin => value,
                SeekOrigin.Current => _position + value,
                SeekOrigin.End => length + value,
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };

            Position = target;
            return _position;
        }

        public override void Flush() { }

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int index, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !leaveOpen)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
