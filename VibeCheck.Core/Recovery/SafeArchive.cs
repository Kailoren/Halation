using System.IO.Compression;
using System.Text;

namespace VibeCheck.Core.Recovery;

/// <summary>Bounds applied when reading an untrusted archive.</summary>
public sealed record ArchiveLimits
{
    public int MaxEntries { get; init; } = 20_000;

    /// <summary>Ceiling on total decompressed bytes across the whole archive.</summary>
    public long MaxTotalBytes { get; init; } = 512L * 1024 * 1024;

    /// <summary>Ceiling on any single entry. Source files far below this are the target.</summary>
    public long MaxFileBytes { get; init; } = 32L * 1024 * 1024;

    /// <summary>
    /// Decompressed-to-compressed ratio above which an entry is treated as a bomb.
    /// Ordinary source and minified JS sit well under 100:1.
    /// </summary>
    public int MaxCompressionRatio { get; init; } = 200;

    public static ArchiveLimits Default { get; } = new();
}

/// <summary>
/// Reads entries out of an untrusted zip without ever writing to disk.
/// </summary>
/// <remarks>
/// <para>
/// This is the scanner's own attack surface. It exists to open archives that are assumed
/// hostile, so it takes the same precautions the tool looks for in others: nothing is
/// extracted to the filesystem, so zip-slip and hostile symlinks are structurally
/// impossible rather than merely guarded against; sizes are enforced during the read
/// rather than read from the central directory, which an attacker controls; and entry
/// counts, per-file size, total size, and compression ratio are all capped so a bomb
/// fails the scan instead of the machine.
/// </para>
/// <para>
/// Traversal sequences in entry names are still rejected. Nothing is written, but those
/// paths are rendered in reports, and a name like <c>../../etc/passwd</c> shown as the
/// location of a finding is misleading on its own.
/// </para>
/// </remarks>
public static class SafeArchive
{
    public sealed record Entry(string Path, byte[] Content);

    /// <summary>
    /// Streams entries whose names pass <paramref name="include"/>, applying every limit.
    /// Rejections append an explanation to <paramref name="warnings"/> so the report can
    /// state what was skipped instead of silently under-reporting.
    /// </summary>
    public static IEnumerable<Entry> ReadEntries(
        ZipArchive archive,
        Func<string, bool> include,
        IList<string> warnings,
        ArchiveLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(include);
        ArgumentNullException.ThrowIfNull(warnings);

        limits ??= ArchiveLimits.Default;

        long totalBytes = 0;
        var examined = 0;

        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (++examined > limits.MaxEntries)
            {
                warnings.Add(
                    $"Archive has more than {limits.MaxEntries:N0} entries; the remainder was not scanned.");
                yield break;
            }

            // Directory markers have an empty name after the trailing slash.
            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            var normalised = Normalise(entry.FullName);

            if (IsUnsafePath(normalised))
            {
                warnings.Add($"Skipped entry with an unsafe path: {Describe(entry.FullName)}");
                continue;
            }

            if (!include(normalised))
            {
                continue;
            }

            if (entry.Length > limits.MaxFileBytes)
            {
                warnings.Add(
                    $"Skipped {normalised}: declared size exceeds {limits.MaxFileBytes / (1024 * 1024)} MB.");
                continue;
            }

            if (IsCompressionBomb(entry, limits))
            {
                warnings.Add(
                    $"Skipped {normalised}: compression ratio exceeds {limits.MaxCompressionRatio}:1.");
                continue;
            }

            if (totalBytes >= limits.MaxTotalBytes)
            {
                warnings.Add(
                    $"Stopped after {limits.MaxTotalBytes / (1024 * 1024)} MB of decompressed content.");
                yield break;
            }

            var budget = Math.Min(limits.MaxFileBytes, limits.MaxTotalBytes - totalBytes);
            byte[]? content;

            try
            {
                content = ReadBounded(entry, budget, cancellationToken);
            }
            catch (InvalidDataException)
            {
                warnings.Add($"Skipped {normalised}: corrupt compressed data.");
                continue;
            }
            catch (IOException)
            {
                warnings.Add($"Skipped {normalised}: unreadable.");
                continue;
            }

            if (content is null)
            {
                warnings.Add($"Skipped {normalised}: expanded beyond its declared size.");
                continue;
            }

            totalBytes += content.Length;
            yield return new Entry(normalised, content);
        }
    }

    /// <summary>
    /// Reads at most <paramref name="budget"/> bytes, returning null if the entry keeps
    /// producing data past that point.
    /// </summary>
    /// <remarks>
    /// The budget is enforced here, during decompression, rather than by trusting
    /// <see cref="ZipArchiveEntry.Length"/>. That value comes from the archive's central
    /// directory and an attacker writes it, so a bomb can declare itself small.
    /// </remarks>
    private static byte[]? ReadBounded(
        ZipArchiveEntry entry,
        long budget,
        CancellationToken cancellationToken)
    {
        using var stream = entry.Open();
        using var buffer = new MemoryStream();

        var chunk = new byte[81920];
        long written = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var read = stream.Read(chunk, 0, chunk.Length);
            if (read == 0)
            {
                break;
            }

            written += read;
            if (written > budget)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static bool IsCompressionBomb(ZipArchiveEntry entry, ArchiveLimits limits) =>
        entry.CompressedLength > 0
        && entry.Length / entry.CompressedLength > limits.MaxCompressionRatio;

    private static string Normalise(string path) => path.Replace('\\', '/').TrimStart('/');

    /// <summary>
    /// Rejects absolute paths, drive-qualified paths, traversal segments, and NTFS
    /// alternate data streams.
    /// </summary>
    private static bool IsUnsafePath(string normalised)
    {
        if (normalised.Length == 0 || normalised.StartsWith('/') || normalised.Contains(':'))
        {
            return true;
        }

        foreach (var segment in normalised.Split('/'))
        {
            if (segment is ".." or "." || segment.EndsWith(' ') || segment.EndsWith('.'))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Renders a hostile entry name safely for display: control characters and newlines in
    /// a path would otherwise let a crafted archive forge lines in the report output.
    /// </summary>
    private static string Describe(string raw)
    {
        var builder = new StringBuilder(raw.Length);

        foreach (var c in raw.AsSpan(0, Math.Min(raw.Length, 120)))
        {
            builder.Append(char.IsControl(c) ? '?' : c);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Decodes recovered bytes as text, rejecting anything that looks binary so the rule
    /// engine is never handed a decompressed image or native payload to regex over.
    /// </summary>
    public static string? DecodeText(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (content.Length == 0)
        {
            return string.Empty;
        }

        // A NUL byte in the first block is the cheapest reliable binary signal.
        var probe = content.AsSpan(0, Math.Min(content.Length, 8000));
        if (probe.Contains((byte)0))
        {
            return null;
        }

        return new UTF8Encoding(false, throwOnInvalidBytes: false).GetString(content);
    }
}
