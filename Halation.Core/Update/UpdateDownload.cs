using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace Halation.Core.Update;

/// <summary>A build fetched to disk, not yet trusted and not yet in place.</summary>
public sealed record DownloadedBuild
{
    public required string Path { get; init; }

    public required long Bytes { get; init; }

    /// <summary>
    /// What arrived, in hex.
    /// </summary>
    /// <remarks>
    /// Recorded and shown, not relied on. The only hash available here comes from the same
    /// place as the file, so it can say the transfer was not corrupted and nothing more.
    /// What decides whether this file may run is its signature; see <see cref="UpdateInstall"/>.
    /// </remarks>
    public required string Sha256 { get; init; }
}

/// <summary>
/// Fetches a release asset to disk.
/// </summary>
/// <remarks>
/// Redirects are followed by hand. A release download starts at github.com and is handed on to
/// a storage host, and an automatic redirect would follow that hop to wherever it pointed:
/// the address to be trusted is checked once and then the client goes wherever it is sent. Here
/// every hop is checked against the same allowlist as the first.
/// </remarks>
public static class UpdateDownload
{
    /// <summary>Ceiling on a downloaded build. A release is around 65 MB; this is a runaway stop.</summary>
    private const long MaxBytes = 512L * 1024 * 1024;

    private const int MaxRedirects = 5;

    private const int BufferSize = 81920;

    public static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler
        {
            // The whole point. See the remarks above.
            AllowAutoRedirect = false,
        };

        var client = new HttpClient(handler)
        {
            // Long enough for a large file on a poor connection, finite so a stalled transfer
            // does not sit in the interface forever claiming to be working.
            Timeout = TimeSpan.FromMinutes(15),
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd($"Halation/{Scanner.Version}");

        return client;
    }

    /// <summary>
    /// Whether a hop is somewhere GitHub serves release assets from.
    /// </summary>
    /// <remarks>
    /// A suffix match with the leading dot present, so <c>notgithubusercontent.com</c> and
    /// <c>githubusercontent.com.example.net</c> are both refused. GitHub has moved asset
    /// hosting between names within this domain more than once, which is why the whole domain
    /// is allowed rather than a list of the hosts in use today.
    /// </remarks>
    public static bool IsAllowedHost(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        return uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
               || uri.Host.Equals("githubusercontent.com", StringComparison.OrdinalIgnoreCase)
               || uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Fetches an asset to <paramref name="stagedPath"/>, reporting progress from 0 to 1.
    /// </summary>
    /// <remarks>
    /// A partial file is removed on any failure, including cancellation. Leaving one behind
    /// would put a truncated executable next to the real one under a name that looks like a
    /// build, which is a bad thing to leave in somebody's folder.
    /// </remarks>
    public static async Task<DownloadedBuild> FetchAsync(
        HttpClient http,
        ReleaseAsset asset,
        string stagedPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(asset);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedPath);

        var start = GitHubReleases.ValidateDownloadUrl(asset.DownloadUrl)
                    ?? throw new InvalidOperationException(
                        "The release names a download address that is not a GitHub release asset.");

        try
        {
            using var response = await FollowAsync(http, start, cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            var expected = asset.Size > 0 ? asset.Size : response.Content.Headers.ContentLength ?? 0;

            if (expected > MaxBytes)
            {
                throw new InvalidOperationException(
                    $"The release asset is {expected / (1024 * 1024)} MB, which is larger than "
                    + "VibeCheck will download.");
            }

            var (bytes, hash) = await WriteAsync(response, stagedPath, expected, progress, cancellationToken)
                .ConfigureAwait(false);

            // Both numbers come from GitHub, so this is a consistency check rather than a
            // security one: it catches a truncated transfer, not a substituted file.
            if (asset.Size > 0 && bytes != asset.Size)
            {
                throw new InvalidOperationException(
                    $"The download stopped at {bytes:N0} bytes; the release lists {asset.Size:N0}.");
            }

            return new DownloadedBuild { Path = stagedPath, Bytes = bytes, Sha256 = hash };
        }
        catch
        {
            Discard(stagedPath);
            throw;
        }
    }

    /// <summary>Walks the redirect chain, checking every hop rather than only the first.</summary>
    private static async Task<HttpResponseMessage> FollowAsync(
        HttpClient http,
        Uri uri,
        CancellationToken cancellationToken)
    {
        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            var response = await http
                .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (!IsRedirect(response.StatusCode))
            {
                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();

            if (location is null)
            {
                throw new InvalidOperationException("The download was redirected to nowhere.");
            }

            uri = location.IsAbsoluteUri ? location : new Uri(uri, location);

            if (!IsAllowedHost(uri))
            {
                throw new InvalidOperationException(
                    $"The download was redirected to {uri.Host}, which is not a GitHub host.");
            }
        }

        throw new InvalidOperationException("The download was redirected too many times.");
    }

    private static bool IsRedirect(HttpStatusCode status) => status is
        HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
        or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    private static async Task<(long Bytes, string Sha256)> WriteAsync(
        HttpResponseMessage response,
        string stagedPath,
        long expected,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        await using var source = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        await using var destination = new FileStream(
            stagedPath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, useAsync: true);

        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[BufferSize];
        long total = 0;
        var lastReported = -1;

        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                break;
            }

            total += read;

            // Checked against the ceiling as it arrives rather than afterwards, because
            // afterwards is a full disk.
            if (total > MaxBytes)
            {
                throw new InvalidOperationException("The download exceeded the size VibeCheck will accept.");
            }

            hasher.AppendData(buffer.AsSpan(0, read));

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);

            if (expected <= 0)
            {
                continue;
            }

            // Reported per whole percent. A progress event per 80 KB chunk is roughly eight
            // hundred dispatcher hops for a release-sized file, all to redraw the same bar.
            var percent = (int)(100 * total / expected);

            if (percent != lastReported)
            {
                lastReported = percent;
                progress?.Report(Math.Clamp(percent / 100d, 0, 1));
            }
        }

        return (total, Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant());
    }

    private static void Discard(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
