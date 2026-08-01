using System.Buffers.Binary;
using System.IO.Compression;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

/// <summary>
/// Covers the NSIS reader against installers built in memory.
/// </summary>
/// <remarks>
/// Synthetic rather than a checked-in installer on purpose: this repository is public and
/// must not carry third-party binaries. The layout these build is the one verified against
/// real installers produced by electron-builder.
/// </remarks>
public class NsisArchiveTests
{
    [Fact]
    public void IsInstaller_is_false_for_a_plain_binary()
    {
        var path = TempFile(NsisBuilder.MinimalPe());

        Assert.False(NsisArchive.IsInstaller(path));
    }

    [Fact]
    public void Recovers_every_payload_in_the_data_section()
    {
        var path = TempFile(NsisBuilder.Build(
            [
                NsisBuilder.Payload("first"u8.ToArray(), compress: true),
                NsisBuilder.Payload("second"u8.ToArray(), compress: false),
            ]));

        var warnings = new List<string>();
        var blobs = NsisArchive.ReadBlobs(path, warnings);

        Assert.Equal(2, blobs.Count);
        Assert.Empty(warnings);

        using var installer = File.OpenRead(path);
        Assert.Equal("first", ReadAll(installer, blobs[0]));
        Assert.Equal("second", ReadAll(installer, blobs[1]));
    }

    [Fact]
    public void Detects_an_installer_as_its_own_kind_rather_than_a_native_binary()
    {
        var path = TempFile(NsisBuilder.Build([NsisBuilder.Payload("x"u8.ToArray(), compress: true)]));

        var descriptor = ArtifactDetector.Detect(path);

        Assert.Equal(ArtifactKind.WindowsInstaller, descriptor.Kind);
    }

    /// <summary>
    /// An installer carries an Authenticode signature after the archive. Reading to the end
    /// of the file instead of the declared archive length treats that as another payload.
    /// </summary>
    [Fact]
    public void Stops_at_the_declared_archive_length_and_ignores_a_trailing_signature()
    {
        var installer = NsisBuilder.Build([NsisBuilder.Payload("only"u8.ToArray(), compress: true)]);
        var withTail = installer.Concat(new byte[4096]).ToArray();

        var path = TempFile(withTail);
        var blobs = NsisArchive.ReadBlobs(path, []);

        Assert.Single(blobs);
    }

    /// <summary>
    /// A solid archive is one stream rather than per-payload blocks, so walking it would
    /// produce nonsense. It has to be refused in words, because silently returning nothing
    /// would report an unexamined installer as one that held nothing.
    /// </summary>
    [Fact]
    public void Refuses_an_archive_whose_header_does_not_decompress_and_says_so()
    {
        var installer = NsisBuilder.Build(
            [NsisBuilder.Payload("x"u8.ToArray(), compress: true)],
            corruptHeaderBlock: true);

        var path = TempFile(installer);
        var warnings = new List<string>();

        var blobs = NsisArchive.ReadBlobs(path, warnings);

        Assert.Empty(blobs);
        Assert.Contains(warnings, w => w.Contains("compression mode", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Identifies_a_seven_zip_payload_by_its_signature()
    {
        Assert.Equal("7z", NsisArchive.SniffFormat([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]));
        Assert.Equal("pe", NsisArchive.SniffFormat([0x4D, 0x5A, 0, 0, 0, 0, 0, 0]));
        Assert.Null(NsisArchive.SniffFormat([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    /// <summary>The payload is routinely 100 MB, so it must not be copied to be read.</summary>
    [Fact]
    public void Opens_a_stored_payload_as_a_seekable_window()
    {
        var path = TempFile(NsisBuilder.Build(
            [NsisBuilder.Payload("abcdefghij"u8.ToArray(), compress: false)]));

        var blobs = NsisArchive.ReadBlobs(path, []);

        using var installer = File.OpenRead(path);
        using var payload = NsisArchive.Open(installer, blobs[0], leaveOpen: true);

        Assert.True(payload.CanSeek);
        Assert.Equal(10, payload.Length);

        payload.Seek(4, SeekOrigin.Begin);
        var buffer = new byte[3];
        payload.ReadExactly(buffer);

        Assert.Equal("efg", System.Text.Encoding.ASCII.GetString(buffer));
    }

    private static string ReadAll(Stream installer, NsisArchive.Blob blob)
    {
        using var stream = NsisArchive.Open(installer, blob, leaveOpen: true);
        using var reader = new StreamReader(stream);

        return reader.ReadToEnd();
    }

    private static string TempFile(byte[] content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"vibecheck-nsis-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, content);

        return path;
    }
}

/// <summary>Builds NSIS-shaped installers in memory.</summary>
internal static class NsisBuilder
{
    internal sealed record PayloadSpec(byte[] Content, bool Compress);

    internal static PayloadSpec Payload(byte[] content, bool compress) => new(content, compress);

    /// <summary>
    /// A minimal but valid native PE32+ image, used as the installer stub.
    /// </summary>
    /// <remarks>
    /// Built by hand rather than borrowed from the test assembly, which is managed: the
    /// detector classifies a managed PE as a .NET assembly before it ever looks for an
    /// installer, so a managed stub tests the wrong branch. Real NSIS stubs are native.
    /// The section table matters as much as the headers, because the overlay offset the
    /// reader uses is derived from it.
    /// </remarks>
    internal static byte[] MinimalPe()
    {
        const int HeadersSize = 0x200;
        const int SectionSize = 0x200;

        var image = new byte[HeadersSize + SectionSize];

        "MZ"u8.CopyTo(image.AsSpan(0));
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3C), 0x40);   // e_lfanew

        var pe = image.AsSpan(0x40);
        "PE\0\0"u8.CopyTo(pe);

        // COFF header.
        var coff = pe[4..];
        BinaryPrimitives.WriteUInt16LittleEndian(coff[0..], 0x8664);          // x64
        BinaryPrimitives.WriteUInt16LittleEndian(coff[2..], 1);               // one section
        BinaryPrimitives.WriteUInt16LittleEndian(coff[16..], 240);            // optional header size
        BinaryPrimitives.WriteUInt16LittleEndian(coff[18..], 0x0022);         // executable, large address

        // Optional header (PE32+). Only the fields a reader validates are filled.
        var opt = coff[20..];
        BinaryPrimitives.WriteUInt16LittleEndian(opt[0..], 0x20B);            // PE32+
        BinaryPrimitives.WriteInt32LittleEndian(opt[32..], 0x1000);           // SectionAlignment
        BinaryPrimitives.WriteInt32LittleEndian(opt[36..], 0x200);            // FileAlignment
        BinaryPrimitives.WriteUInt16LittleEndian(opt[48..], 6);               // MajorSubsystemVersion
        BinaryPrimitives.WriteInt32LittleEndian(opt[56..], 0x2000);           // SizeOfImage
        BinaryPrimitives.WriteInt32LittleEndian(opt[60..], HeadersSize);      // SizeOfHeaders
        BinaryPrimitives.WriteUInt16LittleEndian(opt[68..], 2);               // Subsystem: GUI
        BinaryPrimitives.WriteInt32LittleEndian(opt[108..], 16);              // NumberOfRvaAndSizes

        // All 16 data directories stay zero, which is what makes this native: index 14 is the
        // CLI header, and an empty one is how the detector concludes there is no metadata.

        // Section table, immediately after the optional header.
        var section = opt[240..];
        ".text\0\0\0"u8.CopyTo(section);
        BinaryPrimitives.WriteInt32LittleEndian(section[8..], SectionSize);   // VirtualSize
        BinaryPrimitives.WriteInt32LittleEndian(section[12..], 0x1000);       // VirtualAddress
        BinaryPrimitives.WriteInt32LittleEndian(section[16..], SectionSize);  // SizeOfRawData
        BinaryPrimitives.WriteInt32LittleEndian(section[20..], HeadersSize);  // PointerToRawData
        BinaryPrimitives.WriteUInt32LittleEndian(section[36..], 0x6000_0020); // code, read, execute

        return image;
    }

    internal static byte[] Build(
        IReadOnlyList<PayloadSpec> payloads,
        bool corruptHeaderBlock = false)
    {
        var stub = MinimalPe();

        using var output = new MemoryStream();
        output.Write(stub);

        // The header block: NSIS stores its script here. Its contents are irrelevant to the
        // walker, but its declared inflated size is, because that is what proves the archive
        // is per-block rather than solid.
        var header = new byte[512];
        Random.Shared.NextBytes(header);

        var headerBlock = corruptHeaderBlock
            ? WithCompressedFlag(Random.Shared.GetItems<byte>([1, 2, 3], 64))
            : Block(header, compress: true);

        using var body = new MemoryStream();
        body.Write(headerBlock);

        foreach (var payload in payloads)
        {
            body.Write(Block(payload.Content, payload.Compress));
        }

        var archiveSize = 28 + (int)body.Length;

        var first = new byte[28];
        BinaryPrimitives.WriteInt32LittleEndian(first.AsSpan(0), 0);              // flags
        BinaryPrimitives.WriteUInt32LittleEndian(first.AsSpan(4), 0xDEAD_BEEF);
        "NullsoftInst"u8.CopyTo(first.AsSpan(8));
        BinaryPrimitives.WriteInt32LittleEndian(first.AsSpan(20), header.Length); // inflated header size
        BinaryPrimitives.WriteInt32LittleEndian(first.AsSpan(24), archiveSize);

        output.Write(first);
        output.Write(body.ToArray());

        return output.ToArray();
    }

    private static byte[] Block(byte[] content, bool compress)
    {
        if (!compress)
        {
            var stored = new byte[4 + content.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(stored.AsSpan(0), (uint)content.Length);
            content.CopyTo(stored.AsSpan(4));

            return stored;
        }

        using var buffer = new MemoryStream();
        using (var deflate = new DeflateStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(content);
        }

        return WithCompressedFlag(buffer.ToArray());
    }

    private static byte[] WithCompressedFlag(byte[] compressed)
    {
        var block = new byte[4 + compressed.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(0), (uint)compressed.Length | 0x8000_0000);
        compressed.CopyTo(block.AsSpan(4));

        return block;
    }
}
