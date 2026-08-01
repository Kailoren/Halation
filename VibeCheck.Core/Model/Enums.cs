namespace VibeCheck.Core.Model;

/// <summary>
/// Severity of a single finding.
/// </summary>
/// <remarks>
/// The numeric values are load-bearing: the scoring model caps the overall score by the
/// single worst finding present, so these are compared by value. Keep them ordered.
/// </remarks>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// Grouping used for the per-category subscores shown alongside the overall score.
/// A single flat number is not explainable; these make it actionable.
/// </summary>
public enum FindingCategory
{
    /// <summary>Credentials, API keys, tokens, connection strings.</summary>
    Secrets,

    /// <summary>Known-vulnerable packages and outdated bundled runtimes.</summary>
    Dependencies,

    /// <summary>Transport security, exposed listeners, outbound endpoints, CORS.</summary>
    Network,

    /// <summary>Authentication, authorisation, and access-control weaknesses.</summary>
    Auth,

    /// <summary>Injection sinks, unsafe deserialisation, weak crypto, unsafe file handling.</summary>
    CodeSafety,

    /// <summary>
    /// Signing, packing/obfuscation, and PE hardening flags. This is all that is available
    /// when no source can be recovered, so it is deliberately its own category rather than
    /// being blended into the source-level ones.
    /// </summary>
    BinaryHygiene,
}

/// <summary>
/// What produced a finding. This distinction is a product guarantee, not a detail:
/// only <see cref="Rule"/> findings may drive a do-not-install verdict, because an
/// inferred result is not a defensible basis for telling someone not to run software.
/// </summary>
public enum FindingSource
{
    /// <summary>A deterministic rule, dependency lookup, or secret match.</summary>
    Rule,

    /// <summary>
    /// The optional BYOK deep pass. Advisory only, always labelled as such in the report.
    /// </summary>
    Assisted,
}

/// <summary>
/// Presentation band for the overall score. Derived from the score, which is itself
/// capped by the worst finding, so the band can never contradict the findings list.
/// </summary>
public enum ScoreBand
{
    DoNotInstall,
    SeriousIssues,
    NeedsWork,
    NoKnownIssues,
}

/// <summary>
/// What the dropped artifact turned out to be. Determines which recovery backend runs
/// and, in turn, how much of the code can actually be analysed.
/// </summary>
public enum ArtifactKind
{
    Unknown,

    /// <summary>Managed PE. Decompiles to near-original C#.</summary>
    DotNetAssembly,

    /// <summary>Unmanaged PE. No source recovery is possible; hygiene checks only.</summary>
    NativeWindows,

    /// <summary>A directory or installer containing resources/app.asar.</summary>
    ElectronApp,

    /// <summary>A bare .asar archive.</summary>
    AsarArchive,

    /// <summary>.jar / .war.</summary>
    JavaArchive,

    /// <summary>PyInstaller or similar single-file Python bundle.</summary>
    PythonBundle,

    /// <summary>A folder or archive that already contains readable source.</summary>
    SourceTree,

    /// <summary>A generic archive whose contents still need classifying.</summary>
    Archive,
}
