using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Artifacts;

/// <summary>
/// What a dropped path turned out to be, before any recovery is attempted.
/// </summary>
public sealed record ArtifactDescriptor
{
    public required string Path { get; init; }
    public required ArtifactKind Kind { get; init; }
    public required bool IsDirectory { get; init; }
    public required long Bytes { get; init; }

    /// <summary>Human-readable note on how the kind was determined, shown in the report.</summary>
    public string? Detail { get; init; }

    public string Name => System.IO.Path.GetFileName(Path.TrimEnd(
        System.IO.Path.DirectorySeparatorChar,
        System.IO.Path.AltDirectorySeparatorChar));
}

/// <summary>
/// Identifies a dropped file or folder so the right recovery backend can run.
/// </summary>
/// <remarks>
/// Detection is by content, not extension. An untrusted download is exactly the case where
/// the extension is least trustworthy, and users rename things constantly. Everything here
/// is read-only and bounded: the artifact is never executed, and reads are capped so a
/// malformed or hostile header cannot walk the scanner off a cliff.
/// </remarks>
public static class ArtifactDetector
{
    /// <summary>Enough for every magic-number check below.</summary>
    private const int HeaderBytes = 64;

    private static ReadOnlySpan<byte> ZipMagic => "PK\x03\x04"u8;
    private static ReadOnlySpan<byte> ElfMagic => [0x7F, (byte)'E', (byte)'L', (byte)'F'];

    public static ArtifactDescriptor Detect(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (Directory.Exists(path))
        {
            return DetectDirectory(path);
        }

        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Artifact not found.", path);
        }

        return DetectFile(path);
    }

    private static ArtifactDescriptor DetectFile(string path)
    {
        var info = new FileInfo(path);
        var header = ReadHeader(path);

        var (kind, detail) = ClassifyFile(path, header);

        return new ArtifactDescriptor
        {
            Path = path,
            Kind = kind,
            IsDirectory = false,
            Bytes = info.Length,
            Detail = detail,
        };
    }

    private static (ArtifactKind Kind, string Detail) ClassifyFile(string path, byte[] header)
    {
        if (header.Length >= 4)
        {
            var span = header.AsSpan();

            if (span.StartsWith(ZipMagic))
            {
                return ClassifyZip(path);
            }

            if (span.StartsWith(ElfMagic))
            {
                // Recorded rather than analysed: this scanner's recovery backends are all
                // Windows- and JS-oriented, so an ELF gets an honest "not analysable here"
                // instead of a misleading clean result.
                return (ArtifactKind.Unknown, "ELF binary; not supported by this build.");
            }

            if (span[0] == 'M' && span[1] == 'Z')
            {
                return ClassifyPortableExecutable(path);
            }

            if (LooksLikeAsar(span))
            {
                return (ArtifactKind.AsarArchive, "Electron asar archive (header signature).");
            }
        }

        return LooksLikeText(header)
            ? (ArtifactKind.SourceTree, "Plain text or source file.")
            : (ArtifactKind.Unknown, "Unrecognised file format.");
    }

    /// <summary>
    /// Distinguishes a managed assembly (decompiles to near-original C#) from a native
    /// binary (no source recovery possible at all). This single bit drives the difference
    /// between a full source-level scan and a hygiene-only one.
    /// </summary>
    private static (ArtifactKind, string) ClassifyPortableExecutable(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new PEReader(stream);

            if (reader.HasMetadata)
            {
                return (ArtifactKind.DotNetAssembly, "Managed PE with CLI metadata.");
            }

            // A .NET single-file publish is a native launcher with the managed assemblies
            // embedded, so it has no CLI metadata of its own and would otherwise be filed as
            // an ordinary native binary and silently written off as unreadable.
            return ContainsSingleFileBundle(path)
                ? (ArtifactKind.DotNetSingleFile, ".NET single-file bundle (embedded assemblies).")
                : (ArtifactKind.NativeWindows, "Native PE without CLI metadata.");
        }
        catch (BadImageFormatException)
        {
            return (ArtifactKind.Unknown, "Truncated or malformed PE header.");
        }
        catch (IOException)
        {
            return (ArtifactKind.Unknown, "PE header could not be read.");
        }
    }

    /// <summary>
    /// A zip could be a JAR, an Electron bundle, or plain source. Peek at the entry names
    /// rather than trusting the extension.
    /// </summary>
    private static (ArtifactKind, string) ClassifyZip(string path)
    {
        try
        {
            using var archive = System.IO.Compression.ZipFile.OpenRead(path);

            var names = archive.Entries
                .Take(2000)
                .Select(e => e.FullName.Replace('\\', '/'))
                .ToList();

            if (names.Any(n => n.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase)))
            {
                return (ArtifactKind.JavaArchive, "Zip containing META-INF/MANIFEST.MF.");
            }

            if (names.Any(n => n.EndsWith("resources/app.asar", StringComparison.OrdinalIgnoreCase)))
            {
                return (ArtifactKind.ElectronApp, "Zip containing resources/app.asar.");
            }

            if (names.Any(n => n.EndsWith("package.json", StringComparison.OrdinalIgnoreCase)))
            {
                return (ArtifactKind.SourceTree, "Zip containing package.json.");
            }

            return (ArtifactKind.Archive, "Generic zip archive.");
        }
        catch (InvalidDataException)
        {
            return (ArtifactKind.Unknown, "Corrupt or unreadable zip archive.");
        }
        catch (IOException)
        {
            return (ArtifactKind.Unknown, "Zip archive could not be opened.");
        }
    }

    private static ArtifactDescriptor DetectDirectory(string path)
    {
        var (kind, detail) = ClassifyDirectory(path);

        return new ArtifactDescriptor
        {
            Path = path,
            Kind = kind,
            IsDirectory = true,
            Bytes = DirectorySize(path),
            Detail = detail,
        };
    }

    private static (ArtifactKind, string) ClassifyDirectory(string path)
    {
        // An installed Electron app keeps its code in resources/app.asar next to the exe.
        if (FindShallow(path, "app.asar") is { } asar)
        {
            return (ArtifactKind.ElectronApp, $"Contains {Relative(path, asar)}.");
        }

        if (FindShallow(path, "package.json") is { } pkg)
        {
            return (ArtifactKind.SourceTree, $"Contains {Relative(path, pkg)}.");
        }

        if (EnumerateSafely(path, "*.sln").Concat(EnumerateSafely(path, "*.csproj")).Any())
        {
            return (ArtifactKind.SourceTree, "Contains a .NET project or solution file.");
        }

        var binaries = EnumerateSafely(path, "*.exe").Concat(EnumerateSafely(path, "*.dll")).ToList();

        if (binaries.Count > 0)
        {
            // A published .NET app folder usually holds one single-file launcher plus data.
            // Classifying that as a plain assembly folder finds nothing to decompile and
            // yields an empty, falsely reassuring result.
            if (binaries.Any(b => ClassifyPortableExecutable(b).Item1 == ArtifactKind.DotNetSingleFile))
            {
                return (ArtifactKind.DotNetSingleFile,
                    "Contains a .NET single-file application.");
            }

            return (ArtifactKind.DotNetAssembly, "Contains Windows binaries; will scan each.");
        }

        return EnumerateSafely(path, "*.*").Any()
            ? (ArtifactKind.SourceTree, "Treated as a source tree.")
            : (ArtifactKind.Unknown, "Empty or unreadable directory.");
    }

    /// <summary>
    /// Searches only the top few levels. Electron and .NET layouts put their markers near
    /// the root, and an unbounded recursive search over an untrusted tree is a denial of
    /// service waiting to happen.
    /// </summary>
    private static string? FindShallow(string root, string fileName, int maxDepth = 3)
    {
        var current = new List<string> { root };

        for (var depth = 0; depth <= maxDepth && current.Count > 0; depth++)
        {
            var next = new List<string>();

            foreach (var dir in current)
            {
                var hit = Path.Combine(dir, fileName);
                if (File.Exists(hit))
                {
                    return hit;
                }

                try
                {
                    next.AddRange(Directory.EnumerateDirectories(dir));
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            current = next;
        }

        return null;
    }

    private static IEnumerable<string> EnumerateSafely(string path, string pattern)
    {
        try
        {
            return Directory.EnumerateFiles(path, pattern, SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    private static long DirectorySize(string path)
    {
        long total = 0;

        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return total;
    }

    /// <summary>
    /// The asar container starts with a Chromium Pickle: a 4-byte size field whose value is
    /// 4, then the header sizes, then the JSON directory beginning with {"files".
    /// </summary>
    private static bool LooksLikeAsar(ReadOnlySpan<byte> header)
    {
        if (header.Length < 20 || BitConverter.ToUInt32(header[..4]) != 4)
        {
            return false;
        }

        var json = Encoding.ASCII.GetString(header[16..Math.Min(32, header.Length)]);
        return json.StartsWith("{\"files\"", StringComparison.Ordinal);
    }

    /// <summary>Heuristic: mostly printable with no NUL bytes reads as text.</summary>
    private static bool LooksLikeText(ReadOnlySpan<byte> header)
    {
        if (header.IsEmpty || header.Contains((byte)0))
        {
            return false;
        }

        var printable = 0;
        foreach (var b in header)
        {
            if (b is >= 0x20 and < 0x7F or (byte)'\r' or (byte)'\n' or (byte)'\t')
            {
                printable++;
            }
        }

        return printable >= header.Length * 0.9;
    }

    private static byte[] ReadHeader(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var buffer = new byte[HeaderBytes];
            var read = stream.ReadAtLeast(buffer, HeaderBytes, throwOnEndOfStream: false);
            return buffer[..read];
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>
    /// The fixed signature the .NET host writes into a single-file bundle, used here to tell
    /// a bundled application apart from an ordinary native executable.
    /// </summary>
    private static ReadOnlySpan<byte> BundleSignature =>
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    /// <summary>Streams the file looking for the bundle marker, with overlap across chunks.</summary>
    private static bool ContainsSingleFileBundle(string path)
    {
        const int ChunkSize = 1024 * 1024;

        try
        {
            var info = new FileInfo(path);

            // A bundle carries a whole runtime; anything small enough to rule out is skipped
            // rather than read end to end.
            if (info.Length < 1024 * 1024)
            {
                return false;
            }

            using var stream = File.OpenRead(path);

            var overlap = BundleSignature.Length - 1;
            var buffer = new byte[ChunkSize + overlap];
            var carried = 0;

            while (true)
            {
                var read = stream.Read(buffer, carried, ChunkSize);
                if (read == 0)
                {
                    return false;
                }

                var available = carried + read;
                if (buffer.AsSpan(0, available).IndexOf(BundleSignature) >= 0)
                {
                    return true;
                }

                // Carry the tail forward so a signature straddling two chunks is still found.
                buffer.AsSpan(available - overlap, overlap).CopyTo(buffer);
                carried = overlap;
            }
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

    private static string Relative(string root, string full) =>
        Path.GetRelativePath(root, full).Replace('\\', '/');

    /// <summary>
    /// SHA-256 of the artifact, so a report can be tied to an exact file. Directories hash
    /// their file list and sizes instead, which is enough to detect a changed drop.
    /// </summary>
    public static string ComputeSha256(ArtifactDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        if (!descriptor.IsDirectory)
        {
            using var stream = File.OpenRead(descriptor.Path);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }

        var manifest = new StringBuilder();
        foreach (var file in Directory
            .EnumerateFiles(descriptor.Path, "*", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal))
        {
            try
            {
                manifest.Append(Relative(descriptor.Path, file))
                        .Append('|')
                        .Append(new FileInfo(file).Length)
                        .Append('\n');
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(manifest.ToString())));
    }
}
