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
    /// <summary>
    /// The lowest score range.
    /// </summary>
    /// <remarks>
    /// Deliberately not called "do not install". Advising against installation is a separate
    /// decision driven by blocking rules, and conflating the two produced a real
    /// contradiction in testing: a legitimate application scored 38 and was labelled "Do not
    /// install" while the verdict itself correctly advised nothing of the sort. A low score
    /// means the application has serious problems, not that its user is in danger.
    /// </remarks>
    CriticalIssues,

    SeriousIssues,
    NeedsWork,
    NoKnownIssues,

    /// <summary>
    /// Too little of the artifact could be read for any score to be meaningful.
    /// </summary>
    /// <remarks>
    /// This band exists because of a real failure observed in testing: a self-contained
    /// single-file application produced no readable code at all, and the scan reported
    /// "100/100, no known issues found". Separating coverage from the score is not on its own
    /// enough, because the band label still reads as reassurance. When nothing was read,
    /// the honest output is a refusal to score rather than a perfect one.
    /// </remarks>
    InsufficientCoverage,
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

    /// <summary>
    /// A .NET single-file publish: a native launcher with the managed assemblies embedded.
    /// Looks native to a PE reader, so it needs its own kind to avoid being silently treated
    /// as an unreadable binary.
    /// </summary>
    DotNetSingleFile,

    /// <summary>Unmanaged PE. No source recovery is possible; hygiene checks only.</summary>
    NativeWindows,

    /// <summary>
    /// A Windows installer with an application packed inside it.
    /// </summary>
    /// <remarks>
    /// Its own kind because it is native by every structural test but is not a dead end: the
    /// application is inside, and for an Electron installer that is the difference between no
    /// coverage and reading the whole source. Treating installers as ordinary native binaries
    /// made the tool useless for the case it exists to serve, since an installer is the usual
    /// shape of anything downloaded.
    /// </remarks>
    WindowsInstaller,

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
