using System.IO.Compression;
using System.Text;

using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Covers the .NET single-file bundle reader against containers built from the format
/// specification, including malformed ones.
/// </summary>
public class SingleFileBundleTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-bundle-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    private string Write(byte[] content, string name = "app.exe")
    {
        var path = Path.Combine(_scratch, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    [Fact]
    public void Bundle_IsRecognised() =>
        Assert.True(SingleFileBundle.IsBundle(Write(BundleBuilder.Build(
            ("MyApp.dll", "assembly-bytes", BundleFileType.Assembly)))));

    [Fact]
    public void OrdinaryBinary_IsNotMistakenForABundle()
    {
        // Large enough to pass the size gate, but carrying no marker.
        var filler = new byte[2 * 1024 * 1024];
        Array.Fill(filler, (byte)0x42);

        Assert.False(SingleFileBundle.IsBundle(Write(filler, "plain.exe")));
    }

    [Fact]
    public void SmallFile_IsNotScanned() =>
        Assert.False(SingleFileBundle.IsBundle(Write([1, 2, 3, 4], "tiny.exe")));

    [Fact]
    public void Entries_AreRecoveredWithTheirContent()
    {
        var path = Write(BundleBuilder.Build(
            ("MyApp.dll", "first-assembly", BundleFileType.Assembly),
            ("Helper.dll", "second-assembly", BundleFileType.Assembly),
            ("MyApp.deps.json", """{"runtimeTarget":{}}""", BundleFileType.DepsJson)));

        var warnings = new List<string>();
        var entries = SingleFileBundle.Read(path, warnings);

        Assert.Equal(3, entries.Count);
        Assert.Equal(
            "first-assembly",
            Encoding.UTF8.GetString(entries.Single(e => e.RelativePath == "MyApp.dll").Content));
        Assert.Equal(
            BundleFileType.DepsJson,
            entries.Single(e => e.RelativePath == "MyApp.deps.json").Type);
    }

    /// <summary>
    /// Bundles published with EnableCompressionInSingleFile store entries deflated, with the
    /// uncompressed length recorded separately.
    /// </summary>
    [Fact]
    public void CompressedEntries_AreInflated()
    {
        var payload = string.Concat(Enumerable.Repeat("public class Widget { } ", 400));

        var path = Write(BundleBuilder.BuildCompressed(
            ("Big.dll", payload, BundleFileType.Assembly)));

        var entries = SingleFileBundle.Read(path, []);

        Assert.Equal(payload, Encoding.UTF8.GetString(Assert.Single(entries).Content));
    }

    [Fact]
    public void NativeAndSymbolEntries_AreSkipped()
    {
        var path = Write(BundleBuilder.Build(
            ("MyApp.dll", "managed", BundleFileType.Assembly),
            ("native.dll", "native", BundleFileType.NativeBinary),
            ("MyApp.pdb", "symbols", BundleFileType.Symbols)));

        var entries = SingleFileBundle.Read(path, []);

        Assert.Equal("MyApp.dll", Assert.Single(entries).RelativePath);
    }

    [Fact]
    public void EntryPointingOutsideTheFile_IsRejected()
    {
        var path = Write(BundleBuilder.BuildWithBadOffset(
            ("MyApp.dll", "assembly", BundleFileType.Assembly)));

        var warnings = new List<string>();
        var entries = SingleFileBundle.Read(path, warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("outside the file", StringComparison.Ordinal));
    }

    [Fact]
    public void ImplausibleFileCount_IsRejected()
    {
        var path = Write(BundleBuilder.BuildWithFileCount(
            5_000_000,
            ("MyApp.dll", "assembly", BundleFileType.Assembly)));

        var warnings = new List<string>();

        Assert.Empty(SingleFileBundle.Read(path, warnings));
        Assert.Contains(warnings, w => w.Contains("implausible", StringComparison.Ordinal));
    }

    [Fact]
    public void FileWithoutAMarker_ReportsRatherThanThrows()
    {
        var filler = new byte[2 * 1024 * 1024];
        var warnings = new List<string>();

        Assert.Empty(SingleFileBundle.Read(Write(filler, "plain.exe"), warnings));
        Assert.Contains(warnings, w => w.Contains("marker", StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Builds .NET single-file bundles for the tests, written from the format specification so
/// the round-trip verifies the reader rather than agreeing with it.
/// </summary>
internal static class BundleBuilder
{
    private static ReadOnlySpan<byte> Signature =>
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    /// <summary>Enough filler to clear the reader's minimum-size gate.</summary>
    private const int LauncherSize = 2 * 1024 * 1024;

    public static byte[] Build(params (string Path, string Content, BundleFileType Type)[] files) =>
        BuildCore(compress: false, fileCountOverride: 0, corruptOffset: false, files);

    public static byte[] BuildCompressed(params (string Path, string Content, BundleFileType Type)[] files) =>
        BuildCore(compress: true, fileCountOverride: 0, corruptOffset: false, files);

    public static byte[] BuildWithBadOffset(params (string Path, string Content, BundleFileType Type)[] files) =>
        BuildCore(compress: false, fileCountOverride: 0, corruptOffset: true, files);

    public static byte[] BuildWithFileCount(
        int fileCount,
        params (string Path, string Content, BundleFileType Type)[] files) =>
        BuildCore(compress: false, fileCount, corruptOffset: false, files);

    private static byte[] BuildCore(
        bool compress,
        int fileCountOverride,
        bool corruptOffset,
        (string Path, string Content, BundleFileType Type)[] files)
    {
        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, Encoding.UTF8);

        // A stand-in for the native launcher the bundle is appended to.
        writer.Write(new byte[LauncherSize]);

        var placed = new List<(long Offset, long Size, long Compressed, BundleFileType Type, string Path)>();

        foreach (var (path, content, type) in files)
        {
            var raw = Encoding.UTF8.GetBytes(content);
            var offset = buffer.Position;

            if (compress)
            {
                using var deflated = new MemoryStream();
                using (var stream = new DeflateStream(deflated, CompressionLevel.Optimal, leaveOpen: true))
                {
                    stream.Write(raw);
                }

                var bytes = deflated.ToArray();
                writer.Write(bytes);
                placed.Add((offset, raw.Length, bytes.Length, type, path));
            }
            else
            {
                writer.Write(raw);
                placed.Add((offset, raw.Length, 0, type, path));
            }
        }

        var manifestOffset = buffer.Position;

        // Version 6 is the .NET 6+ format, which carries a per-entry compressed size.
        writer.Write(6u);
        writer.Write(0u);
        writer.Write(fileCountOverride != 0 ? fileCountOverride : placed.Count);
        writer.Write("test-bundle-id");

        // Version 2 added the deps/runtimeconfig locations and a flags word.
        writer.Write(0L);
        writer.Write(0L);
        writer.Write(0L);
        writer.Write(0L);
        writer.Write(0UL);

        foreach (var (offset, size, compressed, type, path) in placed)
        {
            writer.Write(corruptOffset ? long.MaxValue - 1024 : offset);
            writer.Write(size);
            writer.Write(compressed);
            writer.Write((byte)type);
            writer.Write(path);
        }

        // The launcher holds the manifest offset immediately before the marker.
        writer.Write(manifestOffset);
        writer.Write(Signature);

        return buffer.ToArray();
    }
}
