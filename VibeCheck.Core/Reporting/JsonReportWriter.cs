using System.Text.Json;
using System.Text.Json.Serialization;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Reporting;

/// <summary>
/// Serialises a report as JSON, for pipelines rather than people.
/// </summary>
/// <remarks>
/// Written as an explicit shape rather than by reflecting over <see cref="ScanReport"/>, so
/// that renaming an internal property cannot silently break a consumer's parser. The fields
/// that carry the honesty guarantees are present by name: whether the score is meaningful,
/// how much was covered, what could not be checked, and how old the vulnerability data was.
/// </remarks>
public static class JsonReportWriter
{
    private static readonly JsonSerializerOptions Format = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string Write(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        return JsonSerializer.Serialize(new
        {
            schema = 1,
            scanner = report.ScannerVersion,
            scannedAt = report.ScannedAt,
            durationSeconds = Math.Round(report.Duration.TotalSeconds, 2),

            artifact = new
            {
                name = report.ArtifactName,
                kind = report.Kind.ToString(),
                kindLabel = report.KindLabel,
                bytes = report.ArtifactBytes,
                sha256 = report.Sha256,
            },

            verdict = new
            {
                // Consumers must gate on this rather than reading the score blindly: it is
                // false when too little was readable for a number to mean anything.
                scored = report.Verdict.HasMeaningfulScore,
                score = report.Verdict.HasMeaningfulScore ? report.Verdict.Score : (int?)null,
                band = report.Verdict.Band.ToString(),
                bandLabel = report.Verdict.BandLabel,
                adviseAgainstInstall = report.Verdict.AdviseAgainstInstall,
                blockingReasons = report.Verdict.BlockingReasons,
            },

            coverage = new
            {
                percent = report.Coverage.Percent,
                basis = report.Coverage.Basis,
                filesAnalysed = report.Coverage.RecoveredFileCount,
                bytesRecovered = report.Coverage.RecoveredBytes,
                checksNotPossible = report.Coverage.ChecksNotPossible,
            },

            // What the run actually did, so a consumer can weigh a result that took two
            // seconds without having to assume either thoroughness or negligence.
            effort = new
            {
                recoveryMethod = report.Effort.RecoveryMethod,
                filesRecovered = report.Effort.FilesRecovered,
                bytesRecovered = report.Effort.BytesRecovered,
                checksRun = report.Effort.ChecksRun,
                filesChecked = report.Effort.FilesChecked,
                packagesResolved = report.Effort.PackagesResolved,
                packagesChecked = report.Effort.PackagesChecked,
                summary = report.Effort.Describe(report.ScannedAt),
            },

            vulnerabilityData = new
            {
                origin = report.VulnerabilityData.Origin.ToString(),
                source = report.VulnerabilityData.Source,
                asOf = report.VulnerabilityData.Origin == Dependencies.VulnerabilityDataOrigin.None
                    ? null
                    : (DateTimeOffset?)report.VulnerabilityData.AsOf,
                ageInDays = report.VulnerabilityData.AgeInDays(report.ScannedAt),
                ecosystems = report.VulnerabilityData.Ecosystems,
            },

            categoryScores = report.CategoryScores.ToDictionary(
                kv => kv.Key.ToString(),
                kv => kv.Value),

            findings = report.FindingsBySeverity.Select(f => new
            {
                ruleId = f.RuleId,
                title = f.Title,
                severity = f.Severity.ToString(),
                category = f.Category.ToString(),
                source = f.Source.ToString(),
                blocking = f.IsBlocking,
                file = f.FilePath,
                line = f.Line,
                description = f.Description,
                evidence = f.Evidence,
                remediation = f.Remediation,
                reference = f.Reference,
            }),
        }, Format);
    }
}
