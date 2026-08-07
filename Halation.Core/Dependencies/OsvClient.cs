using System.Net.Http.Json;
using System.Text.Json;

namespace VibeCheck.Core.Dependencies;

/// <summary>
/// Talks to the OSV.dev API.
/// </summary>
/// <remarks>
/// <para>
/// OSV is used rather than querying NVD directly for two reasons. NVD allows five requests
/// per thirty seconds without an API key, which for an application carrying two hundred
/// dependencies is roughly twenty minutes per scan; OSV answers the whole set in one or two
/// batched requests with no key. And NVD matches by CPE, which was designed for products
/// rather than package-version tuples and maps poorly onto npm, NuGet and PyPI names.
/// </para>
/// <para>
/// No CVE coverage is lost by this: OSV aggregates CVE data and carries the identifiers as
/// aliases, so findings still cite CVE numbers and link to the NVD entry.
/// </para>
/// </remarks>
public sealed class OsvClient(HttpClient http) : IDisposable
{
    private const string BatchEndpoint = "https://api.osv.dev/v1/querybatch";
    private const string VulnerabilityEndpoint = "https://api.osv.dev/v1/vulns/";

    /// <summary>Queries per batched request. OSV accepts large batches; this keeps them sane.</summary>
    private const int BatchSize = 500;

    /// <summary>Ceiling on distinct advisories fetched, so one dire application cannot stall.</summary>
    private const int MaxAdvisories = 750;

    /// <summary>Concurrent detail fetches. Deliberately modest against a free public service.</summary>
    private const int DetailConcurrency = 8;

    private readonly HttpClient _http = http;

    /// <summary>
    /// Ceiling on a single response. A batch of 1,000 package identifiers answers in well under
    /// a megabyte, and one advisory in a few kilobytes, so this is generous by two orders of
    /// magnitude and still finite.
    /// </summary>
    /// <remarks>
    /// A trusted endpoint over TLS, so the realistic failure is a malformed or runaway reply
    /// rather than an attack. It is bounded anyway, because "the other end is well behaved" is
    /// the assumption this scanner exists to talk people out of making.
    /// </remarks>
    private const long MaxResponseBytes = 64L * 1024 * 1024;

    public static OsvClient Create(TimeSpan? timeout = null)
    {
        var client = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaxResponseBytes,
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd("VibeCheck/0.1 (+security scanner)");

        return new OsvClient(client);
    }

    /// <summary>
    /// Matches dependencies against the database, returning the advisory identifiers that
    /// affect each. Phase one of two: the batch endpoint returns identifiers only.
    /// </summary>
    public async Task<IReadOnlyDictionary<DependencyRef, IReadOnlyList<string>>> MatchAsync(
        IReadOnlyList<DependencyRef> dependencies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        var matches = new Dictionary<DependencyRef, IReadOnlyList<string>>();

        foreach (var batch in dependencies.Chunk(BatchSize))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var payload = new
            {
                queries = batch.Select(d => new
                {
                    package = new { name = d.Name, ecosystem = d.Ecosystem },
                    version = d.Version,
                }).ToArray(),
            };

            using var response = await _http
                .PostAsJsonAsync(BatchEndpoint, payload, cancellationToken)
                .ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            var body = await response.Content
                .ReadFromJsonAsync<JsonElement>(cancellationToken)
                .ConfigureAwait(false);

            if (!body.TryGetProperty("results", out var results)
                || results.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            // Results come back positionally, in the order the queries were sent.
            var index = 0;
            foreach (var result in results.EnumerateArray())
            {
                if (index >= batch.Length)
                {
                    break;
                }

                var ids = ReadIdentifiers(result);
                if (ids.Count > 0)
                {
                    matches[batch[index]] = ids;
                }

                index++;
            }
        }

        return matches;
    }

    private static List<string> ReadIdentifiers(JsonElement result)
    {
        var ids = new List<string>();

        if (!result.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            return ids;
        }

        foreach (var vuln in vulns.EnumerateArray())
        {
            if (vuln.TryGetProperty("id", out var id) && id.GetString() is { Length: > 0 } value)
            {
                ids.Add(value);
            }
        }

        return ids;
    }

    /// <summary>
    /// Fetches full records for the identifiers matched. Phase two of two, run once per
    /// distinct advisory rather than once per affected package.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, Advisory>> FetchAsync(
        IEnumerable<string> identifiers,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        var wanted = identifiers.Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxAdvisories).ToList();
        var advisories = new Dictionary<string, Advisory>(StringComparer.OrdinalIgnoreCase);

        using var limiter = new SemaphoreSlim(DetailConcurrency);
        var gate = new object();

        var fetches = wanted.Select(async id =>
        {
            await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                var advisory = await FetchOneAsync(id, cancellationToken).ConfigureAwait(false);
                if (advisory is null)
                {
                    return;
                }

                lock (gate)
                {
                    advisories[id] = advisory;
                }
            }
            finally
            {
                limiter.Release();
            }
        });

        await Task.WhenAll(fetches).ConfigureAwait(false);

        return advisories;
    }

    private async Task<Advisory?> FetchOneAsync(string id, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http
                .GetAsync(VulnerabilityEndpoint + Uri.EscapeDataString(id), cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content
                .ReadFromJsonAsync<JsonElement>(cancellationToken)
                .ConfigureAwait(false);

            return ParseAdvisory(body);
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A per-request timeout, not the caller cancelling the scan.
            return null;
        }
    }

    /// <summary>Maps an OSV record onto the scanner's own advisory shape.</summary>
    public static Advisory? ParseAdvisory(JsonElement record)
    {
        if (record.ValueKind != JsonValueKind.Object
            || !record.TryGetProperty("id", out var idElement)
            || idElement.GetString() is not { Length: > 0 } id)
        {
            return null;
        }

        return new Advisory
        {
            Id = id,
            Aliases = ReadStringArray(record, "aliases"),
            Summary = ReadString(record, "summary")
                      ?? ReadString(record, "details")?.Split('\n')[0]
                      ?? "No summary was published for this advisory.",
            Details = ReadString(record, "details"),
            CvssScore = ReadCvssScore(record),
            DatabaseSeverity = ReadDatabaseSeverity(record),
            FixedVersions = ReadFixedVersions(record),
            Published = ReadTimestamp(record, "published"),
        };
    }

    /// <summary>
    /// Reads the highest CVSS base score published with the advisory. Advisories carry the
    /// vector rather than the number, so it is computed rather than read.
    /// </summary>
    private static double? ReadCvssScore(JsonElement record)
    {
        if (!record.TryGetProperty("severity", out var severities)
            || severities.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        double? highest = null;

        foreach (var severity in severities.EnumerateArray())
        {
            var score = Cvss.TryComputeBaseScore(ReadString(severity, "score"));
            if (score is not null && (highest is null || score > highest))
            {
                highest = score;
            }
        }

        return highest;
    }

    /// <summary>Falls back to the publishing database's own rating when no vector exists.</summary>
    private static string? ReadDatabaseSeverity(JsonElement record)
    {
        if (record.TryGetProperty("database_specific", out var top)
            && ReadString(top, "severity") is { Length: > 0 } topLevel)
        {
            return topLevel;
        }

        if (!record.TryGetProperty("affected", out var affected)
            || affected.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var entry in affected.EnumerateArray())
        {
            if (entry.TryGetProperty("database_specific", out var specific)
                && ReadString(specific, "severity") is { Length: > 0 } value)
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>
    /// Collects the versions that resolve the advisory, which is the actionable part of the
    /// finding: "upgrade to 4.17.21" is advice a developer can follow.
    /// </summary>
    private static IReadOnlyList<string> ReadFixedVersions(JsonElement record)
    {
        var fixes = new List<string>();

        if (!record.TryGetProperty("affected", out var affected)
            || affected.ValueKind != JsonValueKind.Array)
        {
            return fixes;
        }

        foreach (var entry in affected.EnumerateArray())
        {
            if (!entry.TryGetProperty("ranges", out var ranges)
                || ranges.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var range in ranges.EnumerateArray())
            {
                if (!range.TryGetProperty("events", out var events)
                    || events.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var change in events.EnumerateArray())
                {
                    if (ReadString(change, "fixed") is { Length: > 0 } version
                        && !IsCommitHash(version)
                        && !fixes.Contains(version, StringComparer.Ordinal))
                    {
                        fixes.Add(version);
                    }
                }
            }
        }

        return fixes;
    }

    /// <summary>
    /// Whether a "fixed" value is a git commit rather than a release version.
    /// </summary>
    /// <remarks>
    /// Advisories carry GIT-type ranges alongside ecosystem ones, and those record commit
    /// hashes. Left in, the remediation reads "upgrade to c45d7c49ea75133e52ab22a8e9e13173938e36ff",
    /// which is not something a developer can act on.
    /// </remarks>
    private static bool IsCommitHash(string value) =>
        value.Length >= 7
        && !value.Contains('.')
        && value.All(Uri.IsHexDigit);

    private static string? ReadString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static IReadOnlyList<string> ReadStringArray(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return [.. array.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString()!)
            .Where(s => s.Length > 0)];
    }

    private static DateTimeOffset? ReadTimestamp(JsonElement element, string property) =>
        ReadString(element, property) is { } text
        && DateTimeOffset.TryParse(text, out var parsed)
            ? parsed
            : null;

    public void Dispose() => _http.Dispose();
}
