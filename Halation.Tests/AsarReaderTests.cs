using System.Text;
using System.Text.Json;

using Halation.Core.Recovery;

namespace Halation.Tests;

public class AsarReaderTests
{
    private static IReadOnlyList<AsarReader.AsarEntry> Read(byte[] asar, out List<string> warnings)
    {
        warnings = [];
        using var stream = new MemoryStream(asar);
        return AsarReader.Read(stream, warnings);
    }

    [Fact]
    public void RoundTrip_RecoversFileContents()
    {
        var asar = AsarBuilder.Build(
            ("package.json", "{\"name\":\"demo\"}"),
            ("index.js", "console.log('hello');"));

        var entries = Read(asar, out _);

        Assert.Equal(2, entries.Count);
        Assert.Equal(
            "{\"name\":\"demo\"}",
            AsarReader.AsText(entries.Single(e => e.Path == "package.json")));
        Assert.Equal(
            "console.log('hello');",
            AsarReader.AsText(entries.Single(e => e.Path == "index.js")));
    }

    [Fact]
    public void NestedDirectories_FlattenToForwardSlashPaths()
    {
        var asar = AsarBuilder.Build(
            ("src/renderer/app.js", "export const x = 1;"),
            ("src/main.js", "require('./renderer/app');"));

        var entries = Read(asar, out _);

        Assert.Contains(entries, e => e.Path == "src/renderer/app.js");
        Assert.Contains(entries, e => e.Path == "src/main.js");
    }

    [Fact]
    public void LargerBodies_ReadAtCorrectOffsets()
    {
        // Several differently sized bodies catch off-by-N errors in the offset arithmetic
        // that a single-file archive would not.
        var files = Enumerable.Range(0, 12)
            .Select(i => ($"file{i}.js", new string((char)('a' + i), (i + 1) * 997)))
            .ToArray();

        var entries = Read(AsarBuilder.Build(files), out _);

        Assert.Equal(files.Length, entries.Count);
        foreach (var (path, content) in files)
        {
            Assert.Equal(content, AsarReader.AsText(entries.Single(e => e.Path == path)));
        }
    }

    [Fact]
    public void EmptyArchive_ReadsCleanly()
    {
        var entries = Read(AsarBuilder.MinimalHeader(), out var warnings);

        Assert.Empty(entries);
        Assert.Empty(warnings);
    }

    [Fact]
    public void UnpackedEntry_IsSkippedAndReported()
    {
        var json = """{"files":{"native.node":{"size":10,"offset":"0","unpacked":true}}}""";

        var entries = Read(AsarBuilder.MinimalHeader(json), out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("unpacked", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Every offset in the header is attacker-controlled, so one pointing past the end of
    /// the file must be rejected rather than read.
    /// </summary>
    [Fact]
    public void OffsetBeyondEndOfFile_IsRejected()
    {
        var json = """{"files":{"evil.js":{"size":100000,"offset":"999999999"}}}""";

        var entries = Read(AsarBuilder.MinimalHeader(json), out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("outside the file", StringComparison.Ordinal));
    }

    [Fact]
    public void NegativeSize_IsRejected()
    {
        var json = """{"files":{"evil.js":{"size":-1,"offset":"0"}}}""";

        var entries = Read(AsarBuilder.MinimalHeader(json), out _);

        Assert.Empty(entries);
    }

    [Fact]
    public void TraversalInEntryName_IsSkipped()
    {
        var json = """{"files":{"..":{"size":4,"offset":"0"}}}""";

        var entries = Read(AsarBuilder.MinimalHeader(json), out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("unsafe name", StringComparison.Ordinal));
    }

    [Fact]
    public void CorruptJsonHeader_ReportsRatherThanThrows()
    {
        var entries = Read(AsarBuilder.MinimalHeader("{not json"), out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("not valid JSON", StringComparison.Ordinal));
    }

    [Fact]
    public void TruncatedFile_ReportsRatherThanThrows()
    {
        var entries = Read([1, 2, 3, 4], out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("too small", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ImplausibleHeaderLength_IsRejectedBeforeAllocating()
    {
        // Claims a 3 GB JSON header inside a 20-byte file.
        var buffer = new byte[20];
        BitConverter.GetBytes(4).CopyTo(buffer, 0);
        BitConverter.GetBytes(64).CopyTo(buffer, 4);
        BitConverter.GetBytes(60).CopyTo(buffer, 8);
        BitConverter.GetBytes(int.MaxValue).CopyTo(buffer, 12);

        var entries = Read(buffer, out var warnings);

        Assert.Empty(entries);
        Assert.Contains(warnings, w => w.Contains("implausible", StringComparison.Ordinal));
    }

    [Fact]
    public void BinaryEntry_DecodesAsNull()
    {
        var asar = AsarBuilder.BuildRaw(("icon.png", new byte[] { 0x89, 0x50, 0x00, 0x1A }));

        var entries = Read(asar, out _);

        Assert.Null(AsarReader.AsText(entries.Single()));
    }
}

/// <summary>
/// Builds real asar containers for the tests.
/// </summary>
/// <remarks>
/// Deliberately written from the format specification rather than by calling the reader, so
/// the round-trip tests verify the reader's offset arithmetic instead of agreeing with it.
/// </remarks>
internal static class AsarBuilder
{
    /// <summary>A well-formed header wrapping the supplied JSON directory, with no bodies.</summary>
    public static byte[] MinimalHeader(string json = "{\"files\":{}}") =>
        Assemble(Encoding.UTF8.GetBytes(json), []);

    public static byte[] Build(params (string Path, string Content)[] files) =>
        BuildRaw(files.Select(f => (f.Path, Encoding.UTF8.GetBytes(f.Content))).ToArray());

    public static byte[] BuildRaw(params (string Path, byte[] Content)[] files)
    {
        var tree = new Dictionary<string, object>();
        using var bodies = new MemoryStream();

        foreach (var (path, content) in files)
        {
            var node = new Dictionary<string, object>
            {
                ["size"] = content.Length,
                ["offset"] = bodies.Position.ToString(),
            };

            Insert(tree, path.Split('/'), node);
            bodies.Write(content);
        }

        var json = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["files"] = tree });
        return Assemble(json, bodies.ToArray());
    }

    private static void Insert(Dictionary<string, object> tree, string[] segments, object leaf)
    {
        if (segments.Length == 1)
        {
            tree[segments[0]] = leaf;
            return;
        }

        if (!tree.TryGetValue(segments[0], out var existing))
        {
            existing = new Dictionary<string, object> { ["files"] = new Dictionary<string, object>() };
            tree[segments[0]] = existing;
        }

        var children = (Dictionary<string, object>)((Dictionary<string, object>)existing)["files"];
        Insert(children, segments[1..], leaf);
    }

    /// <summary>
    /// Lays out the Chromium Pickle header. The JSON is padded to a 4-byte boundary, and
    /// the size field at offset 4 is what the reader adds to 8 to find the data section.
    /// </summary>
    private static byte[] Assemble(byte[] json, byte[] bodies)
    {
        var padded = (json.Length + 3) & ~3;

        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer);

        writer.Write(4);                // size of the size field
        writer.Write(padded + 8);       // header size; data begins at 8 + this
        writer.Write(padded + 4);       // header pickle payload size
        writer.Write(json.Length);      // unpadded JSON length
        writer.Write(json);
        writer.Write(new byte[padded - json.Length]);
        writer.Write(bodies);

        return buffer.ToArray();
    }
}
