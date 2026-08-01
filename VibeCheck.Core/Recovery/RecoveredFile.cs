using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Broad language buckets, used by rules to decide which files they apply to.
/// </summary>
public enum SourceLanguage
{
    Unknown,
    CSharp,
    JavaScript,
    TypeScript,
    Python,
    Java,
    Json,
    Config,
    Markup,
    Shell,
}

/// <summary>
/// One unit of source text recovered from an artifact, ready for the rule engine.
/// </summary>
/// <remarks>
/// Recovered content is held in memory rather than written to disk. Extracting an untrusted
/// archive onto the filesystem is the single most dangerous thing a scanner can do, and
/// keeping it in memory removes zip-slip and hostile-symlink risk from the design entirely
/// rather than mitigating it.
/// </remarks>
public sealed record RecoveredFile
{
    /// <summary>Path relative to the artifact root, always forward-slashed.</summary>
    public required string RelativePath { get; init; }

    public required string Content { get; init; }

    public required SourceLanguage Language { get; init; }

    /// <summary>True when this text was reconstructed by a decompiler rather than read
    /// verbatim, so the report can distinguish recovered source from original source.</summary>
    public bool IsDecompiled { get; init; }

    public int LineCount => Content.AsSpan().Count('\n') + 1;

    /// <summary>Maps a file name to its language bucket.</summary>
    public static SourceLanguage LanguageOf(string path)
    {
        var name = Path.GetFileName(path);

        // Environment files carry no extension pattern worth matching on, and they are the
        // single richest source of leaked credentials in vibecoded projects.
        if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase))
        {
            return SourceLanguage.Config;
        }

        return Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".cs" => SourceLanguage.CSharp,
            ".js" or ".jsx" or ".mjs" or ".cjs" => SourceLanguage.JavaScript,
            ".ts" or ".tsx" or ".mts" or ".cts" => SourceLanguage.TypeScript,
            ".py" or ".pyw" => SourceLanguage.Python,
            ".java" or ".kt" => SourceLanguage.Java,
            ".json" => SourceLanguage.Json,
            ".yml" or ".yaml" or ".toml" or ".ini" or ".config" or ".xml" => SourceLanguage.Config,
            ".html" or ".htm" or ".vue" or ".svelte" or ".xaml" => SourceLanguage.Markup,
            ".sh" or ".bash" or ".ps1" or ".bat" or ".cmd" => SourceLanguage.Shell,
            _ => SourceLanguage.Unknown,
        };
    }
}

/// <summary>
/// What a recovery backend produced: the readable source, an honest coverage figure, and
/// any findings that only the recovery stage could observe (signing, packing, and similar).
/// </summary>
public sealed record RecoveryResult
{
    public required IReadOnlyList<RecoveredFile> Files { get; init; }

    public required CoverageReport Coverage { get; init; }

    /// <summary>
    /// Findings produced during recovery itself, for things not visible in source: whether
    /// the binary is signed, whether it is packed, which PE hardening flags are set.
    /// </summary>
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    public static RecoveryResult Empty(string basis, params string[] checksNotPossible) => new()
    {
        Files = [],
        Coverage = new CoverageReport
        {
            Percent = 0,
            Basis = basis,
            ChecksNotPossible = checksNotPossible,
        },
    };
}

/// <summary>Recovers analysable source text from one class of artifact.</summary>
public interface IRecoveryBackend
{
    bool CanHandle(ArtifactKind kind);

    Task<RecoveryResult> RecoverAsync(
        Artifacts.ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default);
}
