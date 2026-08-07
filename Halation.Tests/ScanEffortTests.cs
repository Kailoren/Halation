using Halation.Core;
using Halation.Core.Dependencies;
using Halation.Core.Model;

namespace Halation.Tests;

/// <summary>
/// The receipt exists so a scan that finishes in under two seconds is not read as one that
/// did not run. Its value depends entirely on the numbers being true, so what it must never
/// do is claim work that did not happen.
/// </summary>
public class ScanEffortTests : IDisposable
{
    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), $"halation-effort-{Guid.NewGuid():N}");

    public ScanEffortTests() => Directory.CreateDirectory(_scratch);

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private static ScanEffort Effort(
        int files = 10,
        int packagesResolved = 0,
        int packagesChecked = 0,
        VulnerabilityDataOrigin origin = VulnerabilityDataOrigin.None) => new()
        {
            RecoveryMethod = "decompilation",
            FilesRecovered = files,
            BytesRecovered = 2048,
            ChecksRun = 38,
            FilesChecked = files,
            PackagesResolved = packagesResolved,
            PackagesChecked = packagesChecked,
            VulnerabilityData = origin == VulnerabilityDataOrigin.None
                ? VulnerabilityDataProvenance.Unavailable
                : new VulnerabilityDataProvenance
                {
                    Origin = origin,
                    AsOf = DateTimeOffset.Now,
                    Source = "OSV.dev",
                },
        };

    [Fact]
    public void States_what_was_recovered_and_how()
    {
        var lines = Effort().Describe(DateTimeOffset.Now);

        Assert.Contains(lines, l => l.Contains("10 files", StringComparison.Ordinal)
                                    && l.Contains("decompilation", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("38 checks", StringComparison.Ordinal));
    }

    /// <summary>
    /// Resolved and checked diverge whenever the lookup declined, and reporting the resolved
    /// count as though it had been checked would claim a network answer that never came.
    /// </summary>
    [Fact]
    public void Does_not_claim_packages_were_checked_when_no_lookup_happened()
    {
        var lines = Effort(packagesResolved: 163, packagesChecked: 0).Describe(DateTimeOffset.Now);

        Assert.Contains(lines, l => l.Contains("none of which could be checked", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains("checked 163", StringComparison.Ordinal));
    }

    [Fact]
    public void Reports_a_completed_lookup_with_its_source()
    {
        var lines = Effort(
            packagesResolved: 163,
            packagesChecked: 163,
            origin: VulnerabilityDataOrigin.Live).Describe(DateTimeOffset.Now);

        Assert.Contains(lines, l => l.Contains("checked 163", StringComparison.Ordinal)
                                    && l.Contains("OSV.dev", StringComparison.Ordinal));
    }

    /// <summary>Nothing recovered has to say so, not report zero files as though that were work.</summary>
    [Fact]
    public void Says_plainly_when_nothing_could_be_recovered()
    {
        var effort = Effort(files: 0) with
        {
            RecoveryMethod = ScanEffort.MethodFor(ArtifactKind.NativeWindows),
            FilesChecked = 0,
        };

        var lines = effort.Describe(DateTimeOffset.Now);

        Assert.Contains(lines, l => l.StartsWith("No source could be recovered", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains("checks against", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_real_scan_populates_the_receipt()
    {
        var app = Path.Combine(_scratch, "src");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "Program.cs"), "class P { void M() { } }");

        var report = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);

        Assert.True(report.Effort.ChecksRun > 0);
        Assert.Equal(report.Coverage.RecoveredFileCount, report.Effort.FilesRecovered);
        Assert.NotEmpty(report.Effort.Describe(report.ScannedAt));

        // Dependency checking was off, so nothing may claim to have been checked.
        Assert.Equal(0, report.Effort.PackagesChecked);
    }
}
