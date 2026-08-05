using VibeCheck.Core.Model;

using VibeCheck.Core.Dependencies;

namespace VibeCheck.Core;

/// <summary>
/// How a scan should behave, chiefly around dependency checking and the optional deep pass.
/// </summary>
public sealed record ScanOptions
{
    /// <summary>Whether to check dependencies against vulnerability data at all.</summary>
    public bool CheckDependencies { get; init; } = true;

    /// <summary>
    /// Supplies vulnerability data directly, bypassing the live lookup. For tests, and for a
    /// caller embedding this library that already has an advisory source of its own.
    /// </summary>
    public IVulnerabilitySource? VulnerabilitySource { get; init; }

    /// <summary>
    /// An Anthropic API key, which turns on the optional deep pass.
    /// </summary>
    /// <remarks>
    /// Off unless a key is supplied, and never read from the environment: paying for a scan
    /// has to be a decision someone made, not something that happens because a variable was
    /// set on the machine.
    /// </remarks>
    public string? DeepPassApiKey { get; init; }

    /// <summary>
    /// Runs the deep pass through a Claude Code installation on this machine instead of an API
    /// key, so a reader with a Claude subscription does not have to buy credits twice.
    /// </summary>
    /// <remarks>
    /// Off unless asked for, on the same reasoning as the key: a scan must not start spending
    /// somebody's subscription quota because a tool happened to be installed. Honoured only for
    /// <see cref="Model.Audience.Developer"/>.
    /// </remarks>
    public bool DeepPassUseLocalCli { get; init; }

    /// <summary>Ceiling on files the deep pass sends, since the key holder pays per file.</summary>
    public int DeepPassMaxFiles { get; init; } = DeepPass.DeepPassTriage.DefaultMaxFiles;

    /// <summary>Overrides the deep pass model. Unset uses the current default.</summary>
    public string? DeepPassModel { get; init; }

    /// <summary>True when a deep pass should run: something was chosen to answer it.</summary>
    public bool DeepPassEnabled =>
        !string.IsNullOrWhiteSpace(DeepPassApiKey) || DeepPassUseLocalCli;

    /// <summary>
    /// Who the report is being written for. Findings carry a severity per audience, so this
    /// selects which question the score answers rather than only how it is worded.
    /// </summary>
    public Audience Audience { get; init; } = Audience.Developer;

    /// <summary>
    /// What this application has been said to have a reason to do, or null for the strict
    /// reading in which nothing is accounted for.
    /// </summary>
    /// <remarks>
    /// Null by default and never inferred. A scan that quietened itself because it guessed what
    /// an application probably was would be worse than one that cried wolf, since the reader
    /// would have no idea a judgment had been made on their behalf.
    /// </remarks>
    public DeclaredPurpose? DeclaredPurpose { get; init; }

    /// <summary>Default behaviour: live dependency lookup, no deep pass.</summary>
    public static ScanOptions Default { get; } = new();

    /// <summary>No dependency checking of any kind.</summary>
    public static ScanOptions NoDependencyCheck { get; } = new() { CheckDependencies = false };
}
