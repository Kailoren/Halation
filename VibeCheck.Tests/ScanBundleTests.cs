using VibeCheck.Core;
using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;

namespace VibeCheck.Tests;

/// <summary>
/// Covers the offline bundle and isolate mode: scan normally, then re-examine the same
/// sample on a machine with no network and get the same dependency result.
/// </summary>
public class ScanBundleTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-bundle-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    /// <summary>Stands in for the live source, so tests never touch the network.</summary>
    private sealed class StubSource(VulnerabilityLookupResult result) : IVulnerabilitySource
    {
        public bool RequiresNetwork => true;

        public Task<VulnerabilityLookupResult> LookupAsync(
            IReadOnlyList<DependencyRef> dependencies,
            CancellationToken cancellationToken = default) => Task.FromResult(result);
    }

    private static readonly Advisory KnownAdvisory = new()
    {
        Id = "GHSA-jf85-cpcp-j695",
        Aliases = ["CVE-2021-23337"],
        Summary = "Command injection in lodash",
        CvssScore = 9.8,
        FixedVersions = ["4.17.21"],
    };

    private static readonly DependencyRef Vulnerable = new()
    {
        Ecosystem = "npm",
        Name = "lodash",
        Version = "4.17.20",
        DeclaredIn = "package-lock.json",
    };

    private static VulnerabilityLookupResult LiveResult() => new()
    {
        Matches = [new VulnerabilityMatch(Vulnerable, KnownAdvisory)],
        Provenance = new VulnerabilityDataProvenance
        {
            Origin = VulnerabilityDataOrigin.Live,
            AsOf = DateTimeOffset.Now,
            Source = "OSV.dev",
            Ecosystems = ["npm"],
        },
    };

    /// <summary>An application whose lock file pins a version with a known advisory.</summary>
    private string BuildProject(string name = "app")
    {
        var root = Path.Combine(_scratch, name);
        Directory.CreateDirectory(root);

        File.WriteAllText(Path.Combine(root, "index.js"), "require('lodash');");
        File.WriteAllText(Path.Combine(root, "package-lock.json"), """
            {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}
            """);

        return root;
    }

    [Fact]
    public async Task LiveScan_ReportsTheVulnerabilityAndWritesABundle()
    {
        var project = BuildProject();

        var report = await new Scanner().ScanAsync(project, new ScanOptions
        {
            VulnerabilitySource = new StubSource(LiveResult()),
            BundleDirectory = _scratch,
        });

        Assert.Contains(report.Findings, f => f.RuleId == "VC-DEP-001");
        Assert.Equal(VulnerabilityDataOrigin.Live, report.VulnerabilityData.Origin);

        Assert.NotNull(report.BundlePath);
        Assert.True(File.Exists(report.BundlePath));
    }

    /// <summary>
    /// The point of the whole design: the isolated machine reproduces the dependency result
    /// with no network at all.
    /// </summary>
    [Fact]
    public async Task IsolatedRescan_ReproducesTheLiveResultFromTheBundle()
    {
        var project = BuildProject();

        var live = await new Scanner().ScanAsync(project, new ScanOptions
        {
            VulnerabilitySource = new StubSource(LiveResult()),
            BundleDirectory = _scratch,
        });

        var isolated = await new Scanner().ScanAsync(project, new ScanOptions
        {
            Isolate = true,
            WriteBundle = false,
            BundlePath = live.BundlePath,
        });

        Assert.True(isolated.RanIsolated);
        Assert.Equal(VulnerabilityDataOrigin.ScanBundle, isolated.VulnerabilityData.Origin);

        var offline = Assert.Single(isolated.Findings, f => f.RuleId == "VC-DEP-001");
        var online = Assert.Single(live.Findings, f => f.RuleId == "VC-DEP-001");

        Assert.Equal(online.Title, offline.Title);
        Assert.Equal(online.Severity, offline.Severity);
    }

    /// <summary>
    /// Reusing another artifact's advisories would produce a report that looks thorough and
    /// describes something else entirely.
    /// </summary>
    [Fact]
    public async Task BundleFromADifferentArtifact_IsRefused()
    {
        var first = BuildProject("first");
        var second = BuildProject("second");
        File.WriteAllText(Path.Combine(second, "extra.js"), "// makes the hash differ");

        var live = await new Scanner().ScanAsync(first, new ScanOptions
        {
            VulnerabilitySource = new StubSource(LiveResult()),
            BundleDirectory = _scratch,
        });

        var isolated = await new Scanner().ScanAsync(second, new ScanOptions
        {
            Isolate = true,
            WriteBundle = false,
            BundlePath = live.BundlePath,
        });

        Assert.DoesNotContain(isolated.Findings, f => f.RuleId == "VC-DEP-001");
        Assert.Contains(
            isolated.Coverage.ChecksNotPossible,
            c => c.Contains("different artifact", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// An isolated scan with nothing to check against must say dependencies went unchecked,
    /// never imply they were clean.
    /// </summary>
    [Fact]
    public async Task IsolatedScanWithNoBundle_SaysDependenciesWereNotChecked()
    {
        var report = await new Scanner().ScanAsync(BuildProject(), new ScanOptions
        {
            Isolate = true,
            WriteBundle = false,
            BundlePath = Path.Combine(_scratch, "does-not-exist.json"),
        });

        Assert.DoesNotContain(report.Findings, f => f.RuleId == "VC-DEP-001");
        Assert.Equal(VulnerabilityDataOrigin.None, report.VulnerabilityData.Origin);
        Assert.Contains(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("were not checked", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task IsolatedScan_NeverWritesABundle()
    {
        var report = await new Scanner().ScanAsync(BuildProject(), ScanOptions.Isolated);

        Assert.Null(report.BundlePath);
    }

    /// <summary>
    /// Isolate mode is enforced by which source is built, not by a flag checked later, so a
    /// network-backed source supplied by mistake is rejected rather than silently used.
    /// </summary>
    [Fact]
    public async Task IsolatedScanGivenANetworkSource_Throws() =>
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new Scanner().ScanAsync(BuildProject(), new ScanOptions
            {
                Isolate = true,
                VulnerabilitySource = new StubSource(LiveResult()),
            }));

    [Fact]
    public void Bundle_RoundTripsThroughDisk()
    {
        var path = Path.Combine(_scratch, "round-trip.json");

        ScanBundle.From("app", "abc123", [Vulnerable], LiveResult()).Save(path);

        var loaded = ScanBundle.Load(path);

        Assert.NotNull(loaded);
        Assert.Equal("abc123", loaded.ArtifactSha256);
        Assert.Single(loaded.Advisories);
        Assert.Equal("GHSA-jf85-cpcp-j695", loaded.Advisories[0].Id);
        Assert.Equal(9.8, loaded.Advisories[0].CvssScore);
        Assert.Single(loaded.Matches);
    }

    [Fact]
    public void Bundle_IsSmall()
    {
        var path = Path.Combine(_scratch, "size.json");

        ScanBundle.From("app", "abc123", [Vulnerable], LiveResult()).Save(path);

        // The whole point of the bundle over a full mirror. A handful of advisories should
        // never approach the size of an ecosystem download.
        Assert.True(new FileInfo(path).Length < 16 * 1024);
    }

    [Fact]
    public void CorruptBundle_LoadsAsNullRatherThanThrowing()
    {
        var path = Path.Combine(_scratch, "corrupt.json");
        File.WriteAllText(path, "{ not json");

        Assert.Null(ScanBundle.Load(path));
    }

    [Fact]
    public void MissingBundle_LoadsAsNull() =>
        Assert.Null(ScanBundle.Load(Path.Combine(_scratch, "absent.json")));

    [Fact]
    public async Task DependencyCheckingOff_ReportsThatItWasSkipped()
    {
        var report = await new Scanner().ScanAsync(BuildProject(), ScanOptions.NoDependencyCheck);

        Assert.Equal(VulnerabilityDataOrigin.None, report.VulnerabilityData.Origin);
        Assert.Contains(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("switched off", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A failed lookup must never read as a clean one, which is the single most dangerous
    /// way this feature could fail.
    /// </summary>
    [Fact]
    public async Task FailedLookup_IsReportedAsUnchecked()
    {
        var report = await new Scanner().ScanAsync(BuildProject(), new ScanOptions
        {
            WriteBundle = false,
            VulnerabilitySource = new StubSource(
                VulnerabilityLookupResult.Unavailable("the vulnerability service was unreachable")),
        });

        Assert.DoesNotContain(report.Findings, f => f.RuleId == "VC-DEP-001");
        Assert.Contains(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("unreachable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UnresolvedRanges_AreReportedAsUnchecked()
    {
        var root = Path.Combine(_scratch, "ranges-only");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "package.json"), """
            { "dependencies": { "lodash": "^4.17.0" } }
            """);

        var report = await new Scanner().ScanAsync(root, ScanOptions.NoDependencyCheck);

        Assert.Contains(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("version ranges", StringComparison.OrdinalIgnoreCase));
    }
}
