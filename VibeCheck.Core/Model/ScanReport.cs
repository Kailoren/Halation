namespace VibeCheck.Core.Model;

/// <summary>
/// The complete result of one scan. This is what the in-app report view renders and what
/// the Markdown and JSON exporters serialise, so it must be self-contained: everything
/// needed to interpret the result, including what could not be checked, lives here.
/// </summary>
public sealed record ScanReport
{
    /// <summary>File name of the scanned artifact. The full local path is deliberately
    /// not carried here, so an exported report does not leak the user's directory layout.</summary>
    public required string ArtifactName { get; init; }

    public required ArtifactKind Kind { get; init; }

    /// <summary>Size of the dropped artifact in bytes.</summary>
    public required long ArtifactBytes { get; init; }

    /// <summary>SHA-256 of the artifact, so a result can be tied to an exact file.</summary>
    public required string Sha256 { get; init; }

    public required DateTimeOffset ScannedAt { get; init; }

    public required Verdict Verdict { get; init; }

    public required CoverageReport Coverage { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>
    /// What the application can do, as opposed to what it does wrong.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate list rather than a section of the one above, and the separation is the point:
    /// nothing here reaches the score. Auto-updating and starting with Windows are how a great
    /// many correct programs work, and rating them as defects charged a working application a
    /// whole band for having a feature.
    /// </para>
    /// <para>
    /// Not hidden either. For somebody deciding whether to run a download this can be the most
    /// useful part of the report: an application that replaces its own code is one whose future
    /// behaviour no scan of it describes, and that is worth saying plainly rather than pricing
    /// into a number. See <see cref="Finding.IsCapability"/>.
    /// </para>
    /// </remarks>
    public IReadOnlyList<Finding> Capabilities { get; init; } = [];

    /// <summary>
    /// What this application was said to have a reason to do, or null when nothing was said.
    /// </summary>
    /// <remarks>
    /// Carried on the report and written into every export, so a result that went quiet because
    /// somebody vouched for the application cannot be shown to a third person without also
    /// showing what was vouched for.
    /// </remarks>
    public DeclaredPurpose? Purpose { get; init; }

    /// <summary>Per-category subscores, on the same 0-100 scale as the overall score.</summary>
    public required IReadOnlyDictionary<FindingCategory, int> CategoryScores { get; init; }

    public required Dependencies.VulnerabilityDataProvenance VulnerabilityData { get; init; }

    /// <summary>
    /// What the scan did, so its speed can be read as fast rather than as skipped.
    /// </summary>
    public required ScanEffort Effort { get; init; }

    /// <summary>
    /// Every check and how it ended, passes included.
    /// </summary>
    /// <remarks>
    /// A report of failures alone tells the reader what is wrong and nothing about how much was
    /// looked at, which reads as an accusation rather than an assessment and gives an author no
    /// credit for the parts that were sound. The three states are kept distinct all the way to
    /// the display so a pass is never confused with a check that had nothing to run against.
    /// </remarks>
    public CheckSummary Checks { get; init; } = new();

    /// <summary>Whether the optional BYOK deep pass contributed to this report.</summary>
    public bool DeepPassRan { get; init; }

    /// <summary>
    /// What the deep pass cost the key holder, in US dollars, or null when it did not run.
    /// Stated because the reader is paying for it on their own account and has no other bill
    /// until it appears on their console a day later.
    /// </summary>
    public decimal? DeepPassCost { get; init; }

    /// <summary>
    /// What answered the deep pass, or null when it did not run. Named in the report because
    /// two backends run different models under different settings, so a reader comparing two
    /// scans of the same application needs to know whether the tool changed or the application
    /// did.
    /// </summary>
    public string? DeepPassBackend { get; init; }

    /// <summary>Version of the scanner that produced this report.</summary>
    public required string ScannerVersion { get; init; }

    /// <summary>How long the scan took, for the UI and for spotting pathological inputs.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// Who this report was written for. Taken from the verdict rather than stored twice, so
    /// the ordering, the wording, and the number can never disagree about the reader.
    /// </summary>
    public Audience Audience => Verdict.Audience;

    /// <summary>Findings ordered worst-first for this report's reader.</summary>
    public IEnumerable<Finding> FindingsBySeverity =>
        Findings.OrderByDescending(f => f.SeverityFor(Audience))
                .ThenBy(f => f.Category)
                .ThenBy(f => f.RuleId, StringComparer.Ordinal);

    public int CountOf(Severity severity) =>
        Findings.Count(f => f.SeverityFor(Audience) == severity);

    /// <summary>
    /// What was found, counted at this reader's severities.
    /// </summary>
    /// <remarks>
    /// Phrased here rather than in either caller, so the window and the exported report cannot
    /// disagree. The case worth the length is the last one: the score is the worse of both
    /// readings, so it can sit in the critical band on the strength of findings that are all
    /// informational for whoever is reading. "No issues were found" printed beneath that number
    /// would be the report contradicting itself two lines apart.
    /// </remarks>
    /// <summary>
    /// Said beside the score when a whole class of check could not run, or null when none was
    /// missed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A shipped application with no lock file scores 100/100 under a heading of "no known
    /// issues found" and a coverage meter reading 100% readable, while nothing whatever is
    /// known about the packages inside it. Every word of that is true and the combination
    /// reads as an all-clear. The fact was already in the report, four cards down, which is
    /// three cards further than anybody scrolls before deciding.
    /// </para>
    /// <para>
    /// Deliberately not folded into the score. Coverage is kept separate from the number by
    /// design, and an application whose dependencies are unreadable has not been shown to be
    /// worse, only to be less known. What was wrong was where the caveat sat, not what the
    /// arithmetic did.
    /// </para>
    /// <para>
    /// Silent when an application genuinely declares no dependencies, which is why
    /// <see cref="ScanEffort.ManifestsUnresolved"/> is counted: nothing was skipped there, so
    /// there is nothing to warn about.
    /// </para>
    /// </remarks>
    public string? DependencyCaveat
    {
        get
        {
            if (Effort.PackagesChecked > 0)
            {
                return null;
            }

            if (Effort.PackagesResolved > 0)
            {
                return $"The {Effort.PackagesResolved:N0} dependencies this application declares "
                       + "were not checked against published advisories, so nothing above "
                       + "accounts for them.";
            }

            return Effort.ManifestsUnresolved > 0
                ? "This application declares dependencies but pins none of them, and ships no "
                  + "lock file saying what it actually installed. Nothing is known about the "
                  + "packages inside it, and nothing above accounts for them."
                : null;
        }
    }

    /// <summary>
    /// Share of minified code past which the reader is told, rather than left to infer it from
    /// evidence they cannot read.
    /// </summary>
    /// <remarks>
    /// A majority. Below it there is still a substantial body of readable source behind the
    /// findings, and the note in the coverage limitations covers it without crowding the score.
    /// </remarks>
    public const int MinifiedShareWorthSaying = 50;

    /// <summary>
    /// Said beside the score when most of what was read is a bundle rather than source.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Recovered is not readable, and the coverage meter cannot tell them apart. A real
    /// application reported "100% readable, no known issues found" while 99% of its code was
    /// minified, and every line of evidence it could have quoted was a fragment several
    /// thousand characters wide.
    /// </para>
    /// <para>
    /// Beside the number rather than among the limitations, on the same reasoning as
    /// <see cref="DependencyCaveat"/>: the fact was already in the report, several cards down,
    /// which is several cards further than anybody scrolls before deciding. This one is not a
    /// claim that less was checked, because since matches stopped collapsing per line the same
    /// things are found either way. It is a claim about what the reader can verify.
    /// </para>
    /// </remarks>
    public string? MinificationCaveat =>
        Coverage.MinifiedPercent >= MinifiedShareWorthSaying
            ? $"{Coverage.MinifiedPercent}% of this application's code ships minified. The "
              + "checks still ran against it, but anything quoted below is a fragment of a "
              + "bundle, so judging a finding for yourself is harder here than the coverage "
              + "figure suggests."
            : null;

    /// <summary>
    /// What a statement of purpose moved out of the count, said in the same breath as the count.
    /// </summary>
    /// <remarks>
    /// Without this the summary of an accounted-for scan reads "nothing was found that reaches
    /// you", which is true of the arithmetic and false of the application. The behaviour is
    /// still there and still listed; the sentence beside the number has to admit it.
    /// </remarks>
    private string AccountedForClause =>
        Verdict.AccountedFor.Count == 0
            ? string.Empty
            : $" {Verdict.AccountedFor.Count} further finding"
              + $"{(Verdict.AccountedFor.Count == 1 ? " was" : "s were")} accounted for as "
              + "intended and left out of the count.";

    public string SummaryLine
    {
        get
        {
            var counts = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }
                .Select(severity => (Severity: severity, Count: CountOf(severity)))
                .Where(found => found.Count > 0)
                .Select(found => $"{found.Count} {found.Severity.ToString().ToLowerInvariant()}")
                .ToList();

            if (counts.Count > 0)
            {
                return $"Found {string.Join(", ", counts)}.{AccountedForClause}";
            }

            var informational = CountOf(Severity.Info);

            if (informational == 0)
            {
                return $"No issues were found by the checks that ran.{AccountedForClause}";
            }

            var listed = informational == 1 ? "finding is" : "findings are";

            return Audience == Audience.EndUser
                ? $"Nothing was found that reaches you. {informational} {listed} listed below, "
                  + $"marked as the developer's rather than yours.{AccountedForClause}"
                : $"No issues were found that count against the score. {informational} "
                  + $"informational {listed} listed below.{AccountedForClause}";
        }
    }

    /// <summary>
    /// Findings that do not bear on this reader at all. Counted rather than listed alongside
    /// the rest, so an end user is not handed a page of the developer's problems, but is
    /// still told they were found and looked at.
    /// </summary>
    public IEnumerable<Finding> NotRelevantToReader =>
        Findings.Where(f => !f.AffectsDecisionOf(Audience));

    /// <summary>Human-readable kind, for headers and exports.</summary>
    public string KindLabel => Kind switch
    {
        ArtifactKind.DotNetAssembly => ".NET assembly",
        ArtifactKind.DotNetSingleFile => ".NET single-file application",
        ArtifactKind.NativeWindows => "Native Windows binary",
        ArtifactKind.WindowsInstaller => "Windows installer",
        ArtifactKind.ElectronApp => "Electron application",
        ArtifactKind.AsarArchive => "Electron asar archive",
        ArtifactKind.JavaArchive => "Java archive",
        ArtifactKind.PythonBundle => "Python bundle",
        ArtifactKind.SourceTree => "Source tree",
        ArtifactKind.Archive => "Archive",
        _ => "Unrecognised artifact",
    };
}
