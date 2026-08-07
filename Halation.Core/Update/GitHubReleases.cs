using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Halation.Core.Update;

/// <summary>
/// Reads the published release list and decides whether anything on it is newer than the
/// build that is running.
/// </summary>
/// <remarks>
/// <para>
/// Anonymous, and it has to stay that way. A credential compiled into a shipped application is
/// readable by anyone holding the application, which is a finding this scanner raises against
/// other people's software and would deserve to have raised against its own. The consequence is
/// that the repository has to be public for the check to answer at all; a private one returns
/// "not found" to an anonymous caller and the check reports that it could not look.
/// </para>
/// <para>
/// Nothing about the reader or the machine is sent. This is a plain GET for a public JSON
/// document, and the comparison against the running version happens here rather than there.
/// </para>
/// </remarks>
public static class GitHubReleases
{
    public const string Owner = "Kailoren";

    public const string Repo = "Halation";

    /// <summary>The asset that is a whole application, as opposed to notes or checksums.</summary>
    public const string ExecutableAssetName = "Halation.exe";

    public static string ReleasesEndpoint { get; } =
        $"https://api.github.com/repos/{Owner}/{Repo}/releases?per_page=20";

    /// <summary>Where a reader is sent to fetch a build by hand.</summary>
    public static string ReleasesPageUrl { get; } = $"https://github.com/{Owner}/{Repo}/releases";

    /// <summary>
    /// Short on purpose. This runs at startup and nothing waits on it, so a slow answer should
    /// be abandoned rather than left holding a connection for the session.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>A release list is a few kilobytes; this is generous and still finite.</summary>
    private const long MaxResponseBytes = 4L * 1024 * 1024;

    public static HttpClient CreateClient()
    {
        var client = new HttpClient
        {
            Timeout = Timeout,
            MaxResponseContentBufferSize = MaxResponseBytes,
        };

        // GitHub refuses requests with no user agent. Deliberately says nothing about the
        // machine beyond the product: an update check is not a telemetry channel.
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"Halation/{Scanner.Version}");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        return client;
    }

    /// <summary>
    /// Asks what has been published and compares it with the running build.
    /// </summary>
    /// <remarks>
    /// Never throws for a reason the reader cannot act on. Being offline, being rate limited and
    /// looking at a repository that is not public are all ordinary outcomes of asking, and an
    /// updater that turns any of them into an error dialog trains people to dismiss it.
    /// </remarks>
    public static async Task<UpdateCheckResult> CheckAsync(
        HttpClient http,
        ReleaseVersion current,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);

        try
        {
            using var response = await http.GetAsync(ReleasesEndpoint, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return UpdateCheckResult.Failed(Describe(response.StatusCode));
            }

            var body = await response.Content
                .ReadFromJsonAsync<JsonElement>(cancellationToken)
                .ConfigureAwait(false);

            return Select(Parse(body), current);
        }
        catch (HttpRequestException ex)
        {
            return UpdateCheckResult.Failed($"No answer from GitHub ({ex.Message}).");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return UpdateCheckResult.Failed("GitHub did not answer in time.");
        }
        catch (JsonException)
        {
            return UpdateCheckResult.Failed("GitHub's answer could not be read.");
        }
    }

    private static string Describe(HttpStatusCode status) => status switch
    {
        // The one worth naming precisely: an anonymous caller is told "not found" for a
        // repository that exists but is private, and "the release list is missing" would send
        // somebody looking for the wrong problem.
        HttpStatusCode.NotFound =>
            $"No public release list for {Owner}/{Repo}. It is either private or has no releases.",

        HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests =>
            "GitHub is rate limiting this machine. The check will run again next time.",

        _ => $"GitHub answered {(int)status}.",
    };

    /// <summary>
    /// Maps the release list onto what a check needs, dropping drafts and anything whose tag is
    /// not a version.
    /// </summary>
    public static IReadOnlyList<ReleaseInfo> Parse(JsonElement body)
    {
        if (body.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var releases = new List<ReleaseInfo>();

        foreach (var entry in body.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            // A draft is visible only to the author and is not published software.
            if (entry.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True)
            {
                continue;
            }

            if (ReadString(entry, "tag_name") is not { Length: > 0 } tag
                || !ReleaseVersion.TryParse(tag, out var version))
            {
                continue;
            }

            releases.Add(new ReleaseInfo
            {
                Tag = tag,
                Version = version,
                MarkedPrerelease = entry.TryGetProperty("prerelease", out var pre)
                                   && pre.ValueKind == JsonValueKind.True,
                PageUrl = ReadString(entry, "html_url") ?? ReleasesPageUrl,
                Published = ReadString(entry, "published_at") is { } published
                            && DateTimeOffset.TryParse(published, out var parsed)
                    ? parsed
                    : null,
                Assets = ReadAssets(entry),
            });
        }

        return releases;
    }

    private static IReadOnlyList<ReleaseAsset> ReadAssets(JsonElement release)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var files = new List<ReleaseAsset>();

        foreach (var asset in assets.EnumerateArray())
        {
            // An upload still in progress is listed before it can be fetched.
            if (ReadString(asset, "state") is { Length: > 0 } state
                && !string.Equals(state, "uploaded", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (ReadString(asset, "name") is not { Length: > 0 } name
                || ReadString(asset, "browser_download_url") is not { Length: > 0 } url
                || ValidateDownloadUrl(url) is null)
            {
                continue;
            }

            files.Add(new ReleaseAsset
            {
                Name = name,
                DownloadUrl = url,
                Size = asset.TryGetProperty("size", out var size)
                       && size.ValueKind == JsonValueKind.Number
                       && size.TryGetInt64(out var bytes)
                    ? bytes
                    : 0,
            });
        }

        return files;
    }

    /// <summary>
    /// Whether a download address is one this application will fetch from.
    /// </summary>
    /// <remarks>
    /// The address arrives inside a response rather than from this codebase, which is the
    /// definition of untrusted input no matter how reputable the source. Constrained to the
    /// scheme, the host and the repository path, so a rewritten field cannot point the
    /// downloader at somebody else's server. Redirects are checked separately and just as
    /// strictly; see <see cref="UpdateDownload"/>.
    /// </remarks>
    public static Uri? ValidateDownloadUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Release assets live at /<owner>/<repo>/releases/download/<tag>/<file> and nowhere
        // else, so anything outside that prefix is not a release asset whatever it claims.
        var expected = $"/{Owner}/{Repo}/releases/download/";

        return uri.AbsolutePath.StartsWith(expected, StringComparison.Ordinal) ? uri : null;
    }

    /// <summary>
    /// Picks the newest published release above the running build, if there is one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A prerelease is offered only to somebody already running one. Somebody on a release
    /// build asked for released software, and quietly moving them onto a beta because it
    /// happens to carry a larger number is not an update, it is a change of channel.
    /// </para>
    /// <para>
    /// The list is scanned rather than trusting its order or GitHub's own "latest", which
    /// excludes prereleases entirely and would find nothing at all while this application is
    /// itself a beta.
    /// </para>
    /// </remarks>
    public static UpdateCheckResult Select(IReadOnlyList<ReleaseInfo> releases, ReleaseVersion current)
    {
        ArgumentNullException.ThrowIfNull(releases);

        ReleaseInfo? best = null;

        foreach (var release in releases)
        {
            if (release.IsPrerelease && !current.IsPrerelease)
            {
                continue;
            }

            if (release.Version <= current)
            {
                continue;
            }

            if (best is null || release.Version > best.Version)
            {
                best = release;
            }
        }

        if (best is null)
        {
            return UpdateCheckResult.UpToDate;
        }

        return new UpdateCheckResult
        {
            Outcome = UpdateCheckOutcome.UpdateAvailable,
            Update = new AvailableUpdate
            {
                Current = current,
                Release = best,
                Executable = best.Assets.FirstOrDefault(a => string.Equals(
                    a.Name, ExecutableAssetName, StringComparison.OrdinalIgnoreCase)),
            },
        };
    }

    private static string? ReadString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
