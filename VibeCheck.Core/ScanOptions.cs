using VibeCheck.Core.Dependencies;

namespace VibeCheck.Core;

/// <summary>
/// How a scan should behave, chiefly around dependency checking and network use.
/// </summary>
public sealed record ScanOptions
{
    /// <summary>Whether to check dependencies against vulnerability data at all.</summary>
    public bool CheckDependencies { get; init; } = true;

    /// <summary>
    /// Runs the scan with no network access whatsoever.
    /// </summary>
    /// <remarks>
    /// Intended for examining a sample that a normal scan has already flagged, on a machine
    /// deliberately cut off from everything. Enforced by construction: in this mode no source
    /// holding a network client is built, so an isolated scan cannot make a request through
    /// an oversight elsewhere in the code.
    /// </remarks>
    public bool Isolate { get; init; }

    /// <summary>
    /// Offline data bundle to check against. When unset, an isolated scan looks for one
    /// beside the artifact under its conventional name.
    /// </summary>
    public string? BundlePath { get; init; }

    /// <summary>
    /// Whether a live scan writes an offline bundle for later isolated re-scanning.
    /// </summary>
    public bool WriteBundle { get; init; } = true;

    /// <summary>Where to write the bundle. Defaults to beside the artifact.</summary>
    public string? BundleDirectory { get; init; }

    /// <summary>
    /// Supplies vulnerability data directly, bypassing the tier selection. For tests and for
    /// hosting an ecosystem mirror.
    /// </summary>
    public IVulnerabilitySource? VulnerabilitySource { get; init; }

    /// <summary>Default behaviour: live lookup, bundle written beside the artifact.</summary>
    public static ScanOptions Default { get; } = new();

    /// <summary>No network, bundle only.</summary>
    public static ScanOptions Isolated { get; } = new() { Isolate = true, WriteBundle = false };

    /// <summary>No dependency checking of any kind.</summary>
    public static ScanOptions NoDependencyCheck { get; } = new()
    {
        CheckDependencies = false,
        WriteBundle = false,
    };
}
