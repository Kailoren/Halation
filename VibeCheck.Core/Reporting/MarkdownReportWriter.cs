using System.Globalization;
using System.Text;

using VibeCheck.Core.Model;
using VibeCheck.Core.Rules;
using VibeCheck.Core.Scoring;

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
        WriteChecks(output, report);
        WriteFindings(output, report);
        WriteCapabilities(output, report);
        WriteRuleFamilies(output, report);
        WriteEffort(output, report);
        WriteLimitations(output, report);
        WriteFooter(output, report);

        return output.ToString();
    }

    /// <summary>
    /// What the application can do, kept away from the score.
    /// </summary>
    /// <remarks>
    /// After the findings rather than before, because these are not problems. Present at all
    /// because for somebody deciding whether to run a download they can matter more than
    /// anything above: an application that replaces its own code is one this report does not
    /// describe the future of.
    /// </remarks>
    private static void WriteCapabilities(StringBuilder output, ScanReport report)
    {
        if (report.Capabilities.Count == 0)
        {
            return;
        }

        output.AppendLine("## What this application can do");
        output.AppendLine();
        output.AppendLine(
            "*Not problems, and none of this affects the score. These are things the "
            + "application is built to do that are worth knowing before you run it.*");
        output.AppendLine();

        foreach (var capability in report.Capabilities)
        {
            output.AppendLine($"### {capability.Title}");
            output.AppendLine();
            output.AppendLine(capability.DescriptionFor(report.Audience));
            output.AppendLine();

            if (capability.Location.Length > 0)
            {
                output.AppendLine($"`{capability.Location}`");
                output.AppendLine();
            }

            if (capability.RemediationFor(report.Audience) is { Length: > 0 } advice)
            {
                output.AppendLine($"**Worth checking:** {advice}");
                output.AppendLine();
            }
        }
    }

    /// <summary>
    /// What the letters in the identifiers mean.
    /// </summary>
    /// <remarks>
    /// Only the families this report actually used, so a scan that found two secrets does not
    /// come with a glossary of eight things it did not find. The window shows the same text on
    /// hover; an exported file has nowhere to hover, which is why it is written out here.
    /// Skipped for the end user, whose copy carries no identifiers to explain.
    /// </remarks>
    private static void WriteRuleFamilies(StringBuilder output, ScanReport report)
    {
        if (report.Audience != Audience.Developer)
        {
            return;
        }

        var used = report.Findings
            .Concat(report.Capabilities)
            .Select(f => RuleFamily.PrefixOf(f.RuleId))
            .Where(prefix => prefix is not null)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        if (used.Count == 0)
        {
            return;
        }

        output.AppendLine("## What the identifiers mean");
        output.AppendLine();

        foreach (var prefix in used)
        {
            var id = $"VC-{prefix}";

            output.AppendLine($"**`{id}-*` · {RuleFamily.NameOf(id)}**");
            output.AppendLine();
            output.AppendLine(RuleFamily.DescribeOf(id));
            output.AppendLine();
        }
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

        // What the number is. The artifact reads differently for the person shipping it and
        // the person running it, and this is the worse of those two readings rather than an
        // answer to whichever question the reader was asking, so a bare number would be read
        // as the wrong one.
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

        // How the number was reached, immediately under it. A low score with no account of
        // itself reads as a judgement rather than a measurement, and gives an author no way to
        // tell one serious problem from forty.
        if (verdict.HasMeaningfulScore && verdict.Explanation is { } explanation)
        {
            foreach (var line in explanation.Describe())
            {
                output.AppendLine(line);
            }

            output.AppendLine();
            output.AppendLine(report.Checks.Describe());
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

        output.AppendLine(report.SummaryLine);
        output.AppendLine();

        // Beside the number, for the same reason the window puts it there: a class of check
        // that could not run is not visible in a score, and stating it four sections later is
        // stating it after the reader has decided.
        if (report.DependencyCaveat is { Length: > 0 } caveat)
        {
            output.AppendLine($"> **Not everything could be checked.** {caveat}");
            output.AppendLine();
        }

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

    /// <summary>
    /// Every check and what became of it, passes included.
    /// </summary>
    /// <remarks>
    /// A report listing only failures tells an author what is wrong and nothing about how much
    /// was examined and found sound, which reads as an accusation rather than an assessment.
    /// The three states stay distinct here: a check that passed and a check that had nothing to
    /// run against are not the same result, and merging them is how a scan that read almost
    /// nothing comes out looking clean.
    /// </remarks>
    private static void WriteChecks(StringBuilder output, ScanReport report)
    {
        if (report.Checks.Checks.Count == 0)
        {
            return;
        }

        // Named precisely. This is the rule catalog that runs over recovered source; packaging,
        // dependency and binary checks are separate passes. A section headed "Checks" would
        // imply it accounted for all of them.
        output.AppendLine("## Source code checks");
        output.AppendLine();
        output.AppendLine(report.Checks.Describe());
        output.AppendLine();
        output.AppendLine("*Packaging, dependency and binary checks run separately and are not "
                          + "counted here.*");
        output.AppendLine();

        foreach (var (state, heading) in new[]
                 {
                     (CheckState.FoundIssues, "Found something"),
                     (CheckState.Passed, "Passed"),
                     (CheckState.NotChecked, "Could not run"),
                 })
        {
            var group = report.Checks.Checks
                .Where(c => c.State == state)
                .OrderBy(c => c.Id, StringComparer.Ordinal)
                .ToList();

            if (group.Count == 0)
            {
                continue;
            }

            output.AppendLine($"### {heading} ({group.Count})");
            output.AppendLine();

            foreach (var check in group)
            {
                // The identifier is a support handle for whoever can act on it, and a serial
                // number attached to somebody else's anxiety for whoever cannot. Same rule as
                // the findings list, which this section would otherwise quietly undo.
                var id = report.Audience == Audience.Developer ? $"`{check.Id}` " : string.Empty;

                // The file count is what a pass is worth. A check that examined one file is a
                // far weaker statement than one that examined four hundred, and printing a
                // bare tick would flatten the two.
                output.AppendLine(state == CheckState.NotChecked
                    ? $"- {id}{check.Title} — nothing it applies to was recovered"
                    : $"- {id}{check.Title} — {check.FilesExamined:N0} file"
                      + $"{(check.FilesExamined == 1 ? "" : "s")} examined");
            }

            output.AppendLine();
        }
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

        // Said once for the whole section instead of on each item. Every finding below quotes
        // the code it rests on, so the reader checks the claim against the source rather than
        // against a repeated warning that they stop reading after the second one.
        if (report.Findings.Any(f => f.Source == FindingSource.Assisted))
        {
            output.AppendLine($"Findings marked `{AssistedMarker}` came from the optional AI "
                              + "deep pass. They are reasoned from the code quoted with each "
                              + "one rather than matched by a rule, and none of them can "
                              + "trigger a do-not-install verdict on their own.");
            output.AppendLine();
        }

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

    /// <summary>
    /// Marks an inferred finding in the metadata line, where the rule identifier goes for a
    /// deterministic one. Short on purpose: it is a label, not a warning.
    /// </summary>
    private const string AssistedMarker = "AI";

    private static void WriteFinding(StringBuilder output, Finding finding, Audience audience)
    {
        // Flattened here as well as where the deep pass parses it. Belt and braces on purpose:
        // the parse-time guard protects the one producer that exists today, and this makes the
        // document structurally unable to carry a heading it was not asked for, whoever writes
        // the next producer. A title spanning lines is never legitimate anyway.
        output.AppendLine($"#### {Redaction.Flatten(finding.Title, max: 200)}");
        output.AppendLine();

        // The rule identifier is a support handle for whoever can act on it, and noise to
        // anyone who cannot. An inferred finding carries the marker in the same position, so
        // where a finding came from is legible at a glance without a paragraph about it.
        var source = finding.Source == FindingSource.Assisted
            ? $"`{AssistedMarker}`"
            : $"`{finding.RuleId}`";

        // Weightless findings say so. Without it every entry in the list looks like it counted
        // against the score, and an author reading twelve items has no way to tell which of
        // them actually moved the number.
        var impact = ScoreCalculator.WeightFor(finding.SeverityFor(audience)) == 0
            ? " · no score impact"
            : string.Empty;

        output.AppendLine((audience == Audience.EndUser && finding.Source != FindingSource.Assisted
            ? $"{Humanise(finding.Category)} · `{finding.Location}`"
            : $"{source} · {Humanise(finding.Category)} · `{finding.Location}`") + impact);

        output.AppendLine();

        // Evidence before the claim. The quoted line is the part a reader can check for
        // themselves, and putting it first turns the description into a reading of something
        // in front of them rather than an assertion they have to take on trust. That is worth
        // more on an inferred finding than any wording of a disclaimer, which is why the
        // per-finding hedge that used to sit here is gone: it is said once, in the section
        // heading, instead of on every item until it stops being read.
        if (!string.IsNullOrWhiteSpace(finding.Evidence))
        {
            // A fence longer than anything in the quoted text, so evidence cannot close its own
            // block and continue as document. Markdown allows this precisely because quoted
            // code containing fences is normal.
            var fence = finding.Evidence.Contains("```", StringComparison.Ordinal) ? "````" : "```";

            output.AppendLine(fence);
            output.AppendLine(finding.Evidence);
            output.AppendLine(fence);
            output.AppendLine();
        }

        output.AppendLine(finding.DescriptionFor(audience));
        output.AppendLine();

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

    private static string Humanise(FindingCategory category) => category.Humanise();

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F1} GB",
    };
}
