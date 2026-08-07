using System.Text.Json;

using Halation.Core.Update;

namespace Halation.Tests;

/// <summary>
/// Reading the release list and deciding what, if anything, to offer.
/// </summary>
/// <remarks>
/// Everything the check acts on arrives inside somebody else's JSON, including the address the
/// downloader would be pointed at. These tests are mostly about what is refused.
/// </remarks>
public class UpdateCheckTests
{
    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement;

    private static string Release(
        string tag,
        bool prerelease = false,
        bool draft = false,
        string? assetName = "Halation.exe",
        string? assetUrl = null,
        long size = 66446645) =>
        $$"""
          {
            "tag_name": "{{tag}}",
            "prerelease": {{(prerelease ? "true" : "false")}},
            "draft": {{(draft ? "true" : "false")}},
            "html_url": "https://github.com/Kailoren/Halation/releases/tag/{{tag}}",
            "published_at": "2026-08-04T12:00:00Z",
            "assets": [
              {
                "name": "{{assetName}}",
                "state": "uploaded",
                "size": {{size}},
                "browser_download_url": "{{assetUrl
                    ?? $"https://github.com/Kailoren/Halation/releases/download/{tag}/{assetName}"}}"
              }
            ]
          }
          """;

    private static ReleaseVersion Version(string text)
    {
        Assert.True(ReleaseVersion.TryParse(text, out var version));

        return version;
    }

    // ---- Reading the list --------------------------------------------------

    [Fact]
    public void ReadsAReleaseAndItsAsset()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.2.0")}]"));

        var release = Assert.Single(releases);

        Assert.Equal("v0.2.0", release.Tag);
        Assert.Equal(Version("0.2.0"), release.Version);
        Assert.False(release.IsPrerelease);

        var asset = Assert.Single(release.Assets);

        Assert.Equal("Halation.exe", asset.Name);
        Assert.Equal(66446645, asset.Size);
    }

    /// <summary>A draft is visible only to its author and is not published software.</summary>
    [Fact]
    public void SkipsDrafts() =>
        Assert.Empty(GitHubReleases.Parse(Json($"[{Release("v0.2.0", draft: true)}]")));

    /// <summary>
    /// A tag that is not a version is not an error, it is somebody tagging something else in
    /// the same repository.
    /// </summary>
    [Fact]
    public void SkipsTagsThatAreNotVersions() =>
        Assert.Empty(GitHubReleases.Parse(Json($"[{Release("nightly")}]")));

    [Fact]
    public void SkipsAssetsStillUploading()
    {
        var releases = GitHubReleases.Parse(Json(
            """
            [{
              "tag_name": "v0.2.0", "prerelease": false, "draft": false,
              "html_url": "https://github.com/Kailoren/Halation/releases/tag/v0.2.0",
              "assets": [{
                "name": "Halation.exe", "state": "starter", "size": 10,
                "browser_download_url":
                  "https://github.com/Kailoren/Halation/releases/download/v0.2.0/Halation.exe"
              }]
            }]
            """));

        Assert.Empty(Assert.Single(releases).Assets);
    }

    [Fact]
    public void SurvivesRubbish()
    {
        Assert.Empty(GitHubReleases.Parse(Json("{}")));
        Assert.Empty(GitHubReleases.Parse(Json("[]")));
        Assert.Empty(GitHubReleases.Parse(Json("[1, \"two\", null]")));
    }

    // ---- Where a download may come from ------------------------------------

    [Theory]

    // Not GitHub at all.
    [InlineData("https://example.com/Kailoren/Halation/releases/download/v1/Halation.exe")]

    // A host that ends in the right letters but is not the right host.
    [InlineData("https://notgithub.com/Kailoren/Halation/releases/download/v1/Halation.exe")]

    // The right host, somewhere else on it.
    [InlineData("https://github.com/Kailoren/Halation/raw/main/evil.exe")]

    // Somebody else's repository.
    [InlineData("https://github.com/someone/else/releases/download/v1/Halation.exe")]

    // Not encrypted.
    [InlineData("http://github.com/Kailoren/Halation/releases/download/v1/Halation.exe")]
    [InlineData("file:///C:/Windows/System32/cmd.exe")]
    [InlineData("not a url")]
    [InlineData(null)]
    public void RefusesDownloadAddressesThatAreNotReleaseAssets(string? url) =>
        Assert.Null(GitHubReleases.ValidateDownloadUrl(url));

    [Fact]
    public void AcceptsARealReleaseAssetAddress() =>
        Assert.NotNull(GitHubReleases.ValidateDownloadUrl(
            "https://github.com/Kailoren/Halation/releases/download/v0.1.0-beta/Halation.exe"));

    /// <summary>An asset whose address is refused is dropped rather than carried along.</summary>
    [Fact]
    public void DropsAssetsPointingElsewhere()
    {
        var releases = GitHubReleases.Parse(Json(
            $"[{Release("v0.2.0", assetUrl: "https://example.com/Halation.exe")}]"));

        Assert.Empty(Assert.Single(releases).Assets);
    }

    [Theory]
    [InlineData("https://github.com/anything", true)]
    [InlineData("https://objects.githubusercontent.com/x", true)]
    [InlineData("https://release-assets.githubusercontent.com/x", true)]
    [InlineData("https://githubusercontent.com/x", true)]

    // The two shapes a suffix check gets wrong when the leading dot is forgotten.
    [InlineData("https://notgithubusercontent.com/x", false)]
    [InlineData("https://githubusercontent.com.example.net/x", false)]
    [InlineData("http://objects.githubusercontent.com/x", false)]
    public void ChecksEveryRedirectHost(string url, bool allowed) =>
        Assert.Equal(allowed, UpdateDownload.IsAllowedHost(new Uri(url)));

    // ---- Choosing what to offer --------------------------------------------

    [Fact]
    public void OffersNothingWhenNothingIsNewer()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.1.0")}]"));

        Assert.Equal(UpdateCheckOutcome.UpToDate, GitHubReleases.Select(releases, Version("0.1.0")).Outcome);
        Assert.Equal(UpdateCheckOutcome.UpToDate, GitHubReleases.Select(releases, Version("0.2.0")).Outcome);
        Assert.Equal(UpdateCheckOutcome.UpToDate, GitHubReleases.Select([], Version("0.1.0")).Outcome);
    }

    [Fact]
    public void OffersTheNewestRatherThanTheFirstListed()
    {
        var releases = GitHubReleases.Parse(Json(
            $"[{Release("v0.2.0")},{Release("v0.4.0")},{Release("v0.3.0")}]"));

        var result = GitHubReleases.Select(releases, Version("0.1.0"));

        Assert.Equal(UpdateCheckOutcome.UpdateAvailable, result.Outcome);
        Assert.Equal(Version("0.4.0"), result.Update!.Version);
        Assert.NotNull(result.Update.Executable);
    }

    /// <summary>
    /// Somebody on a release build asked for released software. Moving them onto a beta because
    /// its number is larger is a change of channel, not an update.
    /// </summary>
    [Fact]
    public void DoesNotPushAReleaseBuildOntoAPrerelease()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.3.0-beta", prerelease: true)}]"));

        Assert.Equal(UpdateCheckOutcome.UpToDate, GitHubReleases.Select(releases, Version("0.2.0")).Outcome);
    }

    /// <summary>Somebody already on a beta is offered the next one, and the release too.</summary>
    [Fact]
    public void OffersPrereleasesToSomebodyRunningOne()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.2.0-beta", prerelease: true)}]"));

        var result = GitHubReleases.Select(releases, Version("0.1.0-beta"));

        Assert.Equal(UpdateCheckOutcome.UpdateAvailable, result.Outcome);
        Assert.Equal(Version("0.2.0-beta"), result.Update!.Version);
    }

    /// <summary>
    /// A release marked prerelease on GitHub counts as one even when its tag looks final. The
    /// two disagree often enough that trusting either alone is wrong.
    /// </summary>
    [Fact]
    public void HonoursTheFlagAsWellAsTheTag()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.3.0", prerelease: true)}]"));

        Assert.True(Assert.Single(releases).IsPrerelease);
        Assert.Equal(UpdateCheckOutcome.UpToDate, GitHubReleases.Select(releases, Version("0.2.0")).Outcome);
    }

    /// <summary>
    /// A release with notes and no binary is still worth mentioning; it just cannot be
    /// installed from here, and the difference is kept rather than collapsed into "no update".
    /// </summary>
    [Fact]
    public void AnnouncesAReleaseWithNoExecutable()
    {
        var releases = GitHubReleases.Parse(Json($"[{Release("v0.2.0", assetName: "notes.md")}]"));

        var result = GitHubReleases.Select(releases, Version("0.1.0"));

        Assert.Equal(UpdateCheckOutcome.UpdateAvailable, result.Outcome);
        Assert.Null(result.Update!.Executable);
    }
}
