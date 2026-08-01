using System.IO.Compression;
using System.Text.Json;

namespace VibeCheck.Core.Dependencies;

/// <summary>
/// A locally downloaded copy of the OSV database, for machines that are permanently offline.
/// </summary>
/// <remarks>
/// <para>
/// Only worth taking when a machine will never see a network. For the far commoner case of
/// scanning normally and then re-examining one sample in isolation, the per-scan bundle is
/// the right tool and is thousands of times smaller.
/// </para>
/// <para>
/// Downloads are per ecosystem because sizes differ by two orders of magnitude: at the time
/// of writing NuGet is about 2 MB and npm about 200 MB, against 1.3 GB for everything. A
/// .NET-only user should not be asked to store the JavaScript ecosystem.
/// </para>
/// </remarks>
public sealed class OsvMirror(string directory)
{
    private const string BucketBase = "https://storage.googleapis.com/osv-vulnerabilities";

    /// <summary>Ecosystems worth offering, in the order most users will want them.</summary>
    public static IReadOnlyList<string> SupportedEcosystems { get; } =
        ["NuGet", "PyPI", "npm", "Maven", "Go", "crates.io"];

    private readonly string _directory = directory;

    public string Directory => _directory;

    /// <summary>
    /// Ecosystem names such as "crates.io" contain characters that are awkward in a file
    /// name, so they are reduced to a safe form rather than used verbatim.
    /// </summary>
    private string ArchivePath(string ecosystem) =>
        Path.Combine(_directory, $"{Sanitise(ecosystem)}.zip");

    private static string Sanitise(string ecosystem) =>
        string.Concat(ecosystem.Select(c => char.IsLetterOrDigit(c) ? c : '_'));

    /// <summary>Ecosystems already downloaded, with their file sizes and ages.</summary>
    public IReadOnlyList<MirrorEcosystemStatus> Status()
    {
        var statuses = new List<MirrorEcosystemStatus>();

        foreach (var ecosystem in SupportedEcosystems)
        {
            var path = ArchivePath(ecosystem);

            statuses.Add(File.Exists(path)
                ? new MirrorEcosystemStatus(ecosystem, true, new FileInfo(path).Length,
                    File.GetLastWriteTimeUtc(path))
                : new MirrorEcosystemStatus(ecosystem, false, 0, null));
        }

        return statuses;
    }

    /// <summary>Asks the server how large an ecosystem is, before committing to the download.</summary>
    public static async Task<long?> MeasureAsync(
        HttpClient http,
        string ecosystem,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);

        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Head,
                $"{BucketBase}/{Uri.EscapeDataString(ecosystem)}/all.zip");

            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            return response.IsSuccessStatusCode ? response.Content.Headers.ContentLength : null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    /// <summary>
    /// Downloads one ecosystem's advisories. Writes to a temporary file and moves it into
    /// place, so an interrupted download cannot leave a half-written mirror that would
    /// silently under-report.
    /// </summary>
    public async Task DownloadAsync(
        HttpClient http,
        string ecosystem,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrWhiteSpace(ecosystem);

        System.IO.Directory.CreateDirectory(_directory);

        var target = ArchivePath(ecosystem);
        var temporary = target + ".partial";

        using (var response = await http
                   .GetAsync($"{BucketBase}/{Uri.EscapeDataString(ecosystem)}/all.zip",
                       HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                   .ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();

            await using var source = await response.Content
                .ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using var destination = File.Create(temporary);

            var buffer = new byte[81920];
            long written = 0;

            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);

                written += read;
                progress?.Report(written);
            }
        }

        File.Move(temporary, target, overwrite: true);
    }

    /// <summary>Builds a source that answers from whatever has been downloaded.</summary>
    public IVulnerabilitySource CreateSource()
    {
        var available = Status().Where(s => s.Downloaded).ToList();

        return available.Count == 0
            ? new NoVulnerabilitySource(
                "No offline vulnerability mirror has been downloaded, so dependencies were not checked.")
            : new MirrorVulnerabilitySource(this, available);
    }

    internal IEnumerable<Advisory> ReadAdvisories(string ecosystem, out DateTimeOffset asOf)
    {
        var path = ArchivePath(ecosystem);
        asOf = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTimeOffset.MinValue;

        return File.Exists(path) ? ReadArchive(path) : [];
    }

    /// <summary>Reads every advisory record out of one ecosystem archive.</summary>
    private static IEnumerable<MirrorRecord> ReadArchiveRecords(string path)
    {
        using var archive = ZipFile.OpenRead(path);

        foreach (var entry in archive.Entries)
        {
            if (!entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            MirrorRecord? record = null;

            try
            {
                using var stream = entry.Open();
                using var document = JsonDocument.Parse(stream);

                var advisory = OsvClient.ParseAdvisory(document.RootElement);
                if (advisory is not null)
                {
                    record = new MirrorRecord(advisory, ReadAffected(document.RootElement));
                }
            }
            catch (JsonException) { }
            catch (InvalidDataException) { }

            if (record is not null)
            {
                yield return record;
            }
        }
    }

    private static IEnumerable<Advisory> ReadArchive(string path) =>
        ReadArchiveRecords(path).Select(r => r.Advisory);

    internal static IEnumerable<MirrorRecord> Records(string path) => ReadArchiveRecords(path);

    internal string PathFor(string ecosystem) => ArchivePath(ecosystem);

    /// <summary>Extracts which packages and version ranges an advisory applies to.</summary>
    private static IReadOnlyList<AffectedPackage> ReadAffected(JsonElement record)
    {
        var affected = new List<AffectedPackage>();

        if (!record.TryGetProperty("affected", out var entries)
            || entries.ValueKind != JsonValueKind.Array)
        {
            return affected;
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("package", out var package)
                || package.TryGetProperty("name", out var nameElement) is false
                || nameElement.GetString() is not { Length: > 0 } name)
            {
                continue;
            }

            var explicitVersions = new List<string>();
            if (entry.TryGetProperty("versions", out var versions)
                && versions.ValueKind == JsonValueKind.Array)
            {
                explicitVersions.AddRange(versions.EnumerateArray()
                    .Where(v => v.ValueKind == JsonValueKind.String)
                    .Select(v => v.GetString()!));
            }

            var ranges = new List<(string Introduced, string? Fixed)>();
            var unevaluable = false;

            if (entry.TryGetProperty("ranges", out var rangeArray)
                && rangeArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var range in rangeArray.EnumerateArray())
                {
                    var type = range.TryGetProperty("type", out var t) ? t.GetString() : null;

                    // GIT ranges are commit graphs, not version orderings, and cannot be
                    // evaluated against a package version at all.
                    if (string.Equals(type, "GIT", StringComparison.OrdinalIgnoreCase))
                    {
                        unevaluable = true;
                        continue;
                    }

                    if (!range.TryGetProperty("events", out var events)
                        || events.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    string? introduced = null;

                    foreach (var change in events.EnumerateArray())
                    {
                        if (change.TryGetProperty("introduced", out var i))
                        {
                            introduced = i.GetString();
                        }
                        else if (change.TryGetProperty("fixed", out var f))
                        {
                            ranges.Add((introduced ?? "0", f.GetString()));
                            introduced = null;
                        }
                        else if (change.TryGetProperty("last_affected", out var last))
                        {
                            ranges.Add((introduced ?? "0", null));
                            _ = last;
                            introduced = null;
                        }
                    }

                    if (introduced is not null)
                    {
                        ranges.Add((introduced, null));
                    }
                }
            }

            affected.Add(new AffectedPackage(name, explicitVersions, ranges, unevaluable));
        }

        return affected;
    }
}

/// <summary>Whether one ecosystem has been downloaded, and how big and old it is.</summary>
public sealed record MirrorEcosystemStatus(
    string Ecosystem,
    bool Downloaded,
    long Bytes,
    DateTimeOffset? DownloadedAt);

internal sealed record AffectedPackage(
    string Name,
    IReadOnlyList<string> ExplicitVersions,
    IReadOnlyList<(string Introduced, string? Fixed)> Ranges,
    bool HasUnevaluableRange);

internal sealed record MirrorRecord(Advisory Advisory, IReadOnlyList<AffectedPackage> Affected);
