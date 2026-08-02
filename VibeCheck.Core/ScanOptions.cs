using VibeCheck.Core.Model;

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

    /// <summary>
    /// An Anthropic API key, which turns on the optional deep pass.
    /// </summary>
    /// <remarks>
    /// Off unless a key is supplied, and never read from the environment: paying for a scan
    /// has to be a decision someone made, not something that happens because a variable was
    /// set on the machine. Ignored entirely in <see cref="Isolate"/> mode, which promises no
    /// network access at all.
    /// </remarks>
    public string? DeepPassApiKey { get; init; }

    /// <summary>
    /// Runs the deep pass through a Claude Code installation on this machine instead of an API
    /// key, so a reader with a Claude subscription does not have to buy credits twice.
    /// </summary>
    /// <remarks>
    /// Off unless asked for, on the same reasoning as the key: a scan must not start spending
    /// somebody's subscription quota because a tool happened to be installed. Honoured only for
    /// <see cref="Model.Audience.Developer"/>, and ignored in <see cref="Isolate"/> mode, which
    /// promises no network access; a local CLI still makes requests.
    /// </remarks>
    public bool DeepPassUseLocalCli { get; init; }

    /// <summary>Ceiling on files the deep pass sends, since the key holder pays per file.</summary>
    public int DeepPassMaxFiles { get; init; } = DeepPass.DeepPassTriage.DefaultMaxFiles;

    /// <summary>Overrides the deep pass model. Unset uses the current default.</summary>
    public string? DeepPassModel { get; init; }

    /// <summary>
    /// True when a deep pass should run: something was chosen to answer it, and the scan can
    /// reach the network.
    /// </summary>
    public bool DeepPassEnabled =>
        !Isolate && (!string.IsNullOrWhiteSpace(DeepPassApiKey) || DeepPassUseLocalCli);

    /// <summary>Default behaviour: live lookup, bundle written beside the artifact, no deep pass.</summary>
    /// <summary>
    /// Who the report is being written for. Findings carry a severity per audience, so this
    /// selects which question the score answers rather than only how it is worded.
    /// </summary>
    public Audience Audience { get; init; } = Audience.Developer;

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
