namespace Halation.Core.Update;

/// <summary>One file attached to a release.</summary>
public sealed record ReleaseAsset
{
    public required string Name { get; init; }

    /// <summary>Where it can be fetched. Validated before use; see <see cref="GitHubReleases"/>.</summary>
    public required string DownloadUrl { get; init; }

    /// <summary>What the release says it weighs, used to size the progress bar.</summary>
    public required long Size { get; init; }
}

/// <summary>One published release, as much of it as an update check needs.</summary>
public sealed record ReleaseInfo
{
    public required string Tag { get; init; }

    public required ReleaseVersion Version { get; init; }

    /// <summary>
    /// What the release itself claims, kept separately from what the tag looks like.
    /// </summary>
    /// <remarks>
    /// A tag can be a prerelease by its suffix, a release can be marked prerelease on GitHub,
    /// and the two disagree often enough that treating either alone as the answer is wrong.
    /// Both are consulted; see <see cref="GitHubReleases.Select"/>.
    /// </remarks>
    public required bool MarkedPrerelease { get; init; }

    public required string PageUrl { get; init; }

    public DateTimeOffset? Published { get; init; }

    public IReadOnlyList<ReleaseAsset> Assets { get; init; } = [];

    public bool IsPrerelease => MarkedPrerelease || Version.IsPrerelease;
}

/// <summary>A release newer than the one running, and the file that would replace it.</summary>
public sealed record AvailableUpdate
{
    public required ReleaseVersion Current { get; init; }

    public required ReleaseInfo Release { get; init; }

    /// <summary>
    /// The executable attached to the release, or null when the release carries no such file.
    /// </summary>
    /// <remarks>
    /// A release with notes and no binary is a normal thing to publish, and it is still worth
    /// telling someone about. It just cannot be installed from here, so the distinction is kept
    /// rather than collapsed into "no update".
    /// </remarks>
    public ReleaseAsset? Executable { get; init; }

    public ReleaseVersion Version => Release.Version;
}

public enum UpdateCheckOutcome
{
    /// <summary>Nothing published is newer than what is running.</summary>
    UpToDate,

    UpdateAvailable,

    /// <summary>
    /// The question could not be answered. Deliberately not an error: no network, a repository
    /// that is not public, and a rate limit all land here, and none of them are the reader's
    /// problem or worth a dialog.
    /// </summary>
    CouldNotCheck,
}

public sealed record UpdateCheckResult
{
    public required UpdateCheckOutcome Outcome { get; init; }

    public AvailableUpdate? Update { get; init; }

    /// <summary>Why, in one line, when the check could not be made.</summary>
    public string? Detail { get; init; }

    public static UpdateCheckResult UpToDate { get; } = new() { Outcome = UpdateCheckOutcome.UpToDate };

    public static UpdateCheckResult Failed(string detail) => new()
    {
        Outcome = UpdateCheckOutcome.CouldNotCheck,
        Detail = detail,
    };
}
