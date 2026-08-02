using System.Globalization;
using System.Text;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Reporting;

/// <summary>
/// Renders a scan report as Markdown.
/// </summary>
/// <remarks>
/// The ordering is deliberate. The verdict and what it rests on come first, then how much of
/// the application was actually readable, and only then the findings. A reader who stops
/// after the first screen should already know how much weight the result carries, rather
/// than having to reach a caveat at the bottom to discover the scan saw twelve per cent of
/// the code.
/// </remarks>
public static class MarkdownReportWriter
{
    public static string Write(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var output = new StringBuilder();

        WriteHeader(output, report);
        WriteVerdict(output, report);
        WriteCoverage(output, report);
        WriteCategoryScores(output, report);
        WriteFindings(output, report);
        WriteEffort(output, report);
        WriteLimitations(output, report);
        WriteFooter(output, report);

        return output.ToString();
    }

    /// <summary>
    /// States the work, alongside the section that states what was skipped. Without it a scan
    /// that finished in under two seconds looked like one that had not run.
    /// </summary>
    private static void WriteEffort(StringBuilder output, ScanReport report)
    {
        var lines = report.Effort.Describe(report.ScannedAt);
        if (lines.Count == 0)
        {
            return;
        }

        output.AppendLine("## What this scan did");
        output.AppendLine();

        foreach (var line in lines)
        {
            output.AppendLine($"- {line}");
        }

        output.AppendLine();
        output.AppendLine($"All of it in {report.Duration.TotalSeconds:F1}s.");
        output.AppendLine();
    }

    private static void WriteHeader(StringBuilder output, ScanReport report)
    {
        output.AppendLine($"# VibeCheck report: {report.ArtifactName}");
        output.AppendLine();
        output.AppendLine($"- **Type:** {report.KindLabel}");
        output.AppendLine($"- **Size:** {FormatBytes(report.ArtifactBytes)}");
        output.AppendLine($"- **SHA-256:** `{report.Sha256}`");
        output.AppendLine($"- **Scanned:** {report.ScannedAt:yyyy-MM-dd HH:mm} "
                          + $"(took {report.Duration.TotalSeconds:F1}s)");
        output.AppendLine();
    }

    private static void WriteVerdict(StringBuilder output, ScanReport report)
    {
        var verdict = report.Verdict;

        output.AppendLine("## Result");
        output.AppendLine();

        // No number is shown when too little was readable. A score implies the application
        // was examined, and printing one for an artifact that yielded nothing is the most
        // misleading thing this report could do.
        output.AppendLine(verdict.HasMeaningfulScore
            ? $"### {verdict.Score}/100 — {verdict.BandLabel}"
            : $"### {verdict.BandLabel}");
        output.AppendLine();

        // Which question the number answered. The same artifact scores differently for the
        // person shipping it and the person running it, so a bare number is ambiguous rather
        // than merely terse.
        output.AppendLine($"*{verdict.ScoreCaption}.*");
        output.AppendLine();

        if (!verdict.HasMeaningfulScore)
        {
            output.AppendLine("> **No score is given for this artifact.** Too little of it could "
                              + "be read for a score to mean anything. This is not a pass and not "
                              + "a failure: the application was not examined. See Coverage below "
                              + "for what was in the way.");
            output.AppendLine();
        }

        if (verdict.AdviseAgainstInstall)
        {
            output.AppendLine("> **Do not install this application.**");
            output.AppendLine(">");
            output.AppendLine("> The following were found, each of which puts the person running "
                              + "this software at risk:");
            output.AppendLine(">");

            foreach (var reason in verdict.BlockingReasons)
            {
                output.AppendLine($"> - {reason}");
            }

            output.AppendLine();
        }

        var counts = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }
            .Select(s => (Severity: s, Count: report.CountOf(s)))
            .Where(x => x.Count > 0)
            .Select(x => $"{x.Count} {x.Severity.ToString().ToLowerInvariant()}")
            .ToList();

        output.AppendLine(counts.Count == 0
            ? "No issues were found by the checks that ran."
            : $"Found {string.Join(", ", counts)}.");
        output.AppendLine();

        // The single most important sentence in the document.
        output.AppendLine("*A clean result is not proof that an application is safe. Static "
                          + "analysis can show that problems are present; it cannot show that "
                          + "none are.*");
        output.AppendLine();
    }

    private static void WriteCoverage(StringBuilder output, ScanReport report)
    {
        var coverage = report.Coverage;

        output.AppendLine("## Coverage");
        output.AppendLine();
        output.AppendLine($"**{coverage.Percent}% of this application was readable.** {coverage.Basis}");
        output.AppendLine();

        if (coverage.RecoveredFileCount > 0)
        {
            output.AppendLine($"Analysed {coverage.RecoveredFileCount:N0} files "
                              + $"({FormatBytes(coverage.RecoveredBytes)} of source).");
            output.AppendLine();
        }

        if (coverage.Percent < 50)
        {
            output.AppendLine("> Coverage is low, so treat the findings below as a floor rather "
                              + "than a complete picture. Most of this application could not be "
                              + "inspected.");
            output.AppendLine();
        }
    }

    private static void WriteCategoryScores(StringBuilder output, ScanReport report)
    {
        var scored = report.CategoryScores
            .Where(kv => kv.Value < 100)
            .OrderBy(kv => kv.Value)
            .ToList();

        if (scored.Count == 0)
        {
            return;
        }

        output.AppendLine("## Scores by category");
        output.AppendLine();
        output.AppendLine("| Category | Score |");
        output.AppendLine("|---|---|");

        foreach (var (category, score) in scored)
        {
            output.AppendLine($"| {Humanise(category)} | {score}/100 |");
        }

        output.AppendLine();
        output.AppendLine("*Categories not listed had no findings. That means nothing was found "
                          + "there, which is not the same as nothing being there.*");
        output.AppendLine();
    }

    private static void WriteFindings(StringBuilder output, ScanReport report)
    {
        if (report.Findings.Count == 0)
        {
            return;
        }

        var audience = report.Audience;

        output.AppendLine("## Findings");
        output.AppendLine();

        foreach (var severity in new[]
                 {
                     Severity.Critical, Severity.High, Severity.Medium, Severity.Low,
                 })
        {
            var group = report.Findings
                .Where(f => f.SeverityFor(audience) == severity)
                .ToList();

            if (group.Count == 0)
            {
                continue;
            }

            output.AppendLine($"### {severity} ({group.Count})");
            output.AppendLine();

            foreach (var finding in group)
            {
                WriteFinding(output, finding, audience);
            }
        }

        WriteNotYourProblem(output, report, audience);
    }

    /// <summary>
    /// The findings that do not reach this reader, listed briefly rather than dropped.
    /// </summary>
    /// <remarks>
    /// Silently removing them would leave an end user unable to tell a scan that found the
    /// developer's leaked key from one that never looked. Naming them and saying plainly that
    /// they are somebody else's problem is both shorter and more trustworthy than either
    /// hiding them or filing them under the reader's own risks.
    /// </remarks>
    private static void WriteNotYourProblem(
        StringBuilder output,
        ScanReport report,
        Audience audience)
    {
        var others = report.NotRelevantToReader.ToList();
        if (others.Count == 0)
        {
            return;
        }

        output.AppendLine(audience == Audience.EndUser
            ? $"### Found, but not your problem ({others.Count})"
            : $"### Informational ({others.Count})");
        output.AppendLine();

        if (audience == Audience.EndUser)
        {
            output.AppendLine("These were found and judged not to affect you. They are listed so "
                              + "you can see the scan did look at them.");
            output.AppendLine();
        }

        foreach (var finding in others)
        {
            output.AppendLine($"- **{finding.Title}.** {finding.DescriptionFor(audience)}");
        }

        output.AppendLine();
    }

    private static void WriteFinding(StringBuilder output, Finding finding, Audience audience)
    {
        output.AppendLine($"#### {finding.Title}");
        output.AppendLine();

        // The rule identifier is a support handle for whoever can act on it, and noise to
        // anyone who cannot.
        output.AppendLine(audience == Audience.EndUser
            ? $"{Humanise(finding.Category)} · `{finding.Location}`"
            : $"`{finding.RuleId}` · {Humanise(finding.Category)} · `{finding.Location}`");

        if (finding.Source == FindingSource.Assisted)
        {
            // Never presented as equivalent to a deterministic match.
            output.AppendLine();
            output.AppendLine("> Identified by the optional AI deep pass. This is an inferred "
                              + "finding and may be wrong; confirm it before acting.");
        }

        output.AppendLine();
        output.AppendLine(finding.DescriptionFor(audience));
        output.AppendLine();

        if (!string.IsNullOrWhiteSpace(finding.Evidence))
        {
            output.AppendLine("```");
            output.AppendLine(finding.Evidence);
            output.AppendLine("```");
            output.AppendLine();
        }

        if (finding.RemediationFor(audience) is { Length: > 0 } remediation)
        {
            output.AppendLine(audience == Audience.EndUser
                ? $"**What you can do:** {remediation}"
                : $"**How to fix:** {remediation}");
            output.AppendLine();
        }

        // An advisory link is the most useful line in the developer's copy and a dead end in
        // the other: it opens a page about a component the reader cannot upgrade, written for
        // somebody who can.
        if (audience == Audience.Developer && !string.IsNullOrWhiteSpace(finding.Reference))
        {
            output.AppendLine($"Reference: {finding.Reference}");
            output.AppendLine();
        }
    }

    private static void WriteLimitations(StringBuilder output, ScanReport report)
    {
        if (report.Coverage.ChecksNotPossible.Count == 0)
        {
            return;
        }

        output.AppendLine("## What could not be checked");
        output.AppendLine();
        output.AppendLine("These checks did not run against this artifact. Their absence from the "
                          + "findings above means they were not performed, not that they passed.");
        output.AppendLine();

        foreach (var limitation in report.Coverage.ChecksNotPossible.Take(30))
        {
            output.AppendLine($"- {limitation}");
        }

        if (report.Coverage.ChecksNotPossible.Count > 30)
        {
            output.AppendLine($"- ...and {report.Coverage.ChecksNotPossible.Count - 30:N0} more.");
        }

        output.AppendLine();
    }

    private static void WriteFooter(StringBuilder output, ScanReport report)
    {
        var provenance = report.VulnerabilityData;

        output.AppendLine("## Vulnerability data");
        output.AppendLine();
        output.AppendLine($"Dependency checks used {provenance.Describe(report.ScannedAt)}.");
        output.AppendLine();

        // Age is stated rather than merely dated. A result checked against data three months
        // old is a materially weaker claim than one checked a second ago, and the difference
        // is invisible unless the report says so.
        if (provenance.IsStale(report.ScannedAt))
        {
            output.AppendLine($"> **This data is {provenance.AgeInDays(report.ScannedAt)} days old.** "
                              + "Anything published since is not reflected here. Re-run with a "
                              + "network connection for a current answer.");
            output.AppendLine();
        }

        if (report.RanIsolated)
        {
            output.AppendLine("> This scan ran in isolate mode and made no network requests.");
            output.AppendLine();
        }

        if (report.BundlePath is { } bundle)
        {
            output.AppendLine($"An offline data bundle for this artifact was written to "
                              + $"`{Path.GetFileName(bundle)}`. Carry it alongside the artifact to "
                              + "reproduce this dependency result on a machine with no network.");
            output.AppendLine();
        }

        output.AppendLine("---");
        output.AppendLine();
        output.AppendLine($"VibeCheck {report.ScannerVersion}");

        if (report.DeepPassRan)
        {
            output.AppendLine(" · " + DeepPassNote(report));
        }
    }

    /// <summary>
    /// What the deep pass cost, in the terms the reader actually paid in.
    /// </summary>
    /// <remarks>
    /// Three outcomes, and conflating any two of them says something untrue. A pass answered
    /// through a Claude subscription spends quota and bills nothing, so printing its
    /// API-equivalent price would tell somebody their card was charged when it was not. A pass
    /// that never ran costs nothing at all, and "US$0.00" would read as one that ran and was
    /// free.
    /// </remarks>
    private static string DeepPassNote(ScanReport report) => report switch
    {
        { DeepPassBackend: null } =>
            "The optional AI deep pass was requested but did not run; see the limitations above.",

        { DeepPassCost: { } cost } =>
            $"Includes findings from the optional AI deep pass, answered by "
            + $"{report.DeepPassBackend}, which cost {Money(cost)} on your API key.",

        _ => "Includes findings from the optional AI deep pass, answered by "
             + $"{report.DeepPassBackend}. It spent your Claude subscription's quota rather "
             + "than money, so there is no charge to expect.",
    };

    /// <summary>
    /// Rounds to cents, but never down to nothing: a pass that cost a third of a cent is cheap,
    /// not free, and printing "$0.00" would say the wrong one. Invariant so an exported report
    /// reads the same for whoever it is sent to.
    /// </summary>
    private static string Money(decimal dollars) => dollars > 0m && dollars < 0.01m
        ? "under US$0.01"
        : $"US${dollars.ToString("F2", CultureInfo.InvariantCulture)}";

    private static string Humanise(FindingCategory category) => category switch
    {
        FindingCategory.Secrets => "Credentials",
        FindingCategory.Dependencies => "Dependencies",
        FindingCategory.Network => "Network",
        FindingCategory.Auth => "Access control",
        FindingCategory.CodeSafety => "Code safety",
        FindingCategory.BinaryHygiene => "Binary hygiene",
        _ => category.ToString(),
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F1} GB",
    };
}
