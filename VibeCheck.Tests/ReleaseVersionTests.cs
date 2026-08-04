using VibeCheck.Core.Update;

namespace VibeCheck.Tests;

/// <summary>
/// The comparison the updater rests on.
/// </summary>
/// <remarks>
/// Getting this wrong is quiet in both directions. Too eager and the application offers to
/// replace itself with an older build; too shy and a published release is never mentioned to
/// anybody, which looks exactly like having no updater at all.
/// </remarks>
public class ReleaseVersionTests
{
    private static ReleaseVersion Parse(string text)
    {
        Assert.True(ReleaseVersion.TryParse(text, out var version), $"{text} should parse");

        return version;
    }

    [Theory]
    [InlineData("1.2.3", 1, 2, 3, "")]
    [InlineData("v1.2.3", 1, 2, 3, "")]
    [InlineData("V1.2.3", 1, 2, 3, "")]
    [InlineData("0.1.0-beta", 0, 1, 0, "beta")]
    [InlineData("v2.0.0-rc.1", 2, 0, 0, "rc.1")]
    public void ReadsTheUsualShapes(string text, int major, int minor, int patch, string prerelease)
    {
        var version = Parse(text);

        Assert.Equal(major, version.Major);
        Assert.Equal(minor, version.Minor);
        Assert.Equal(patch, version.Patch);
        Assert.Equal(prerelease, version.Prerelease);
    }

    /// <summary>Tags are typed by hand, and "v1.2" is a tag somebody will write.</summary>
    [Fact]
    public void FillsInMissingComponents()
    {
        Assert.Equal(new[] { 1, 2, 0 }, new[] { Parse("1.2").Major, Parse("1.2").Minor, Parse("1.2").Patch });
        Assert.Equal(3, Parse("3").Major);
    }

    /// <summary>Build metadata is not part of the ordering, so it must not reach it.</summary>
    [Fact]
    public void DropsBuildMetadata()
    {
        Assert.Equal(Parse("1.2.3"), Parse("1.2.3+abc1234"));
        Assert.Equal("beta", Parse("1.2.3-beta+abc1234").Prerelease);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("nightly")]
    [InlineData("1.2.3.4")]
    [InlineData("v")]
    public void RefusesWhatIsNotAVersion(string text) =>
        Assert.False(ReleaseVersion.TryParse(text, out _));

    [Fact]
    public void RefusesNull() => Assert.False(ReleaseVersion.TryParse(null, out _));

    [Theory]
    [InlineData("1.0.0", "2.0.0")]
    [InlineData("1.9.0", "1.10.0")]
    [InlineData("1.0.1", "1.0.2")]
    public void OrdersByNumber(string older, string newer) =>
        Assert.True(Parse(older) < Parse(newer));

    /// <summary>
    /// The case the whole type exists for: a beta is older than the release it led to, and
    /// comparing the three numbers alone would call them equal and never offer the release.
    /// </summary>
    [Fact]
    public void APrereleaseIsOlderThanItsRelease() =>
        Assert.True(Parse("0.1.0-beta") < Parse("0.1.0"));

    [Theory]
    [InlineData("1.0.0-alpha", "1.0.0-beta")]
    [InlineData("1.0.0-beta", "1.0.0-beta.1")]
    [InlineData("1.0.0-rc.1", "1.0.0-rc.2")]

    // Numerically, not as text. As text "10" sorts before "2".
    [InlineData("1.0.0-beta.2", "1.0.0-beta.10")]

    // A numeric identifier ranks below an alphanumeric one.
    [InlineData("1.0.0-1", "1.0.0-alpha")]
    public void OrdersPrereleases(string older, string newer) =>
        Assert.True(Parse(older) < Parse(newer));

    [Fact]
    public void EqualVersionsAreNeitherNewerNorOlder()
    {
        Assert.False(Parse("1.2.3") < Parse("v1.2.3"));
        Assert.False(Parse("1.2.3") > Parse("v1.2.3"));
        Assert.True(Parse("1.2.3") <= Parse("1.2.3"));
    }

    [Fact]
    public void PrintsBackWhatItRead()
    {
        Assert.Equal("1.2.3", Parse("v1.2.3").ToString());
        Assert.Equal("0.1.0-beta", Parse("v0.1.0-beta").ToString());
    }

    /// <summary>
    /// The build's own version has to be readable by the same parser, or the check refuses to
    /// run against every release there is.
    /// </summary>
    [Fact]
    public void ReadsTheRunningBuildsVersion() =>
        Assert.True(ReleaseVersion.TryParse(VibeCheck.Core.Scanner.Version, out _));
}
