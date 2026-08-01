using System.IO.Compression;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

public class RecoveryBackendTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-recovery-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    private string At(string name) => Path.Combine(_scratch, name);

    private static async Task<RecoveryResult> RecoverAsync(IRecoveryBackend backend, string path) =>
        await backend.RecoverAsync(ArtifactDetector.Detect(path), CancellationToken.None);

    // ---- Electron ----------------------------------------------------------

    [Fact]
    public async Task Electron_BareAsar_RecoversJavaScript()
    {
        var asar = At("app.asar");
        File.WriteAllBytes(asar, AsarBuilder.Build(
            ("index.js", "const token = 'abc';"),
            ("package.json", "{\"name\":\"demo\"}")));

        var result = await RecoverAsync(new ElectronRecoveryBackend(), asar);

        Assert.Equal(2, result.Files.Count);
        Assert.Contains(result.Files, f => f.Language == SourceLanguage.JavaScript);
        Assert.True(result.Coverage.Percent > 0);
    }

    [Fact]
    public async Task Electron_InstalledAppDirectory_FindsAsarUnderResources()
    {
        var app = At("MyApp");
        Directory.CreateDirectory(Path.Combine(app, "resources"));
        File.WriteAllBytes(
            Path.Combine(app, "resources", "app.asar"),
            AsarBuilder.Build(("main.js", "require('electron');")));

        var result = await RecoverAsync(new ElectronRecoveryBackend(), app);

        Assert.Single(result.Files);
        Assert.Equal("main.js", result.Files[0].RelativePath);
    }

    [Fact]
    public async Task Electron_ZippedApp_ReadsAsarWithoutExtractingToDisk()
    {
        var zip = At("dist.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("MyApp/resources/app.asar");
            using var stream = entry.Open();
            stream.Write(AsarBuilder.Build(("renderer.js", "console.log(1);")));
        }

        var result = await RecoverAsync(new ElectronRecoveryBackend(), zip);

        Assert.Single(result.Files);
        Assert.Equal("renderer.js", result.Files[0].RelativePath);
    }

    [Fact]
    public async Task Electron_VendoredCode_IsSkippedButManifestsAreKept()
    {
        var asar = At("bundled.asar");
        File.WriteAllBytes(asar, AsarBuilder.Build(
            ("index.js", "start();"),
            ("node_modules/left-pad/index.js", "module.exports = 1;"),
            ("node_modules/left-pad/package.json", "{\"version\":\"1.0.0\"}")));

        var result = await RecoverAsync(new ElectronRecoveryBackend(), asar);

        Assert.Contains(result.Files, f => f.RelativePath == "index.js");
        Assert.Contains(result.Files, f => f.RelativePath.EndsWith("left-pad/package.json"));
        Assert.DoesNotContain(result.Files, f => f.RelativePath.EndsWith("left-pad/index.js"));
    }

    // ---- Source ------------------------------------------------------------

    [Fact]
    public async Task Source_Directory_ReadsSourceAndManifests()
    {
        var project = At("project");
        Directory.CreateDirectory(Path.Combine(project, "src"));
        File.WriteAllText(Path.Combine(project, "package.json"), "{\"name\":\"app\"}");
        File.WriteAllText(Path.Combine(project, "src", "index.ts"), "export const x = 1;");
        File.WriteAllText(Path.Combine(project, ".env"), "API_KEY=secret");
        File.WriteAllBytes(Path.Combine(project, "logo.png"), [0x89, 0x50, 0x4E, 0x47, 0x00]);

        var result = await RecoverAsync(new SourceRecoveryBackend(), project);

        Assert.Contains(result.Files, f => f.RelativePath == "package.json");
        Assert.Contains(result.Files, f => f.RelativePath == "src/index.ts");
        Assert.Contains(result.Files, f => f.RelativePath == ".env");
        Assert.DoesNotContain(result.Files, f => f.RelativePath.EndsWith(".png"));
    }

    /// <summary>
    /// A key stripped from source but still baked into the shipped bundle is a live leak,
    /// so build output is read rather than skipped.
    /// </summary>
    [Fact]
    public async Task Source_BuildOutput_IsRead()
    {
        var project = At("built");
        Directory.CreateDirectory(Path.Combine(project, "dist"));
        File.WriteAllText(Path.Combine(project, "dist", "bundle.js"), "var k='leaked';");

        var result = await RecoverAsync(new SourceRecoveryBackend(), project);

        Assert.Contains(result.Files, f => f.RelativePath == "dist/bundle.js");
    }

    [Fact]
    public async Task Source_NodeModules_SkipsCodeButKeepsManifests()
    {
        var project = At("with-deps");
        var dep = Path.Combine(project, "node_modules", "lodash");
        Directory.CreateDirectory(dep);
        File.WriteAllText(Path.Combine(project, "index.js"), "require('lodash');");
        File.WriteAllText(Path.Combine(dep, "package.json"), "{\"version\":\"4.17.20\"}");
        File.WriteAllText(Path.Combine(dep, "lodash.js"), "// thousands of lines");

        var result = await RecoverAsync(new SourceRecoveryBackend(), project);

        Assert.Contains(result.Files, f => f.RelativePath == "index.js");
        Assert.Contains(result.Files, f => f.RelativePath.EndsWith("lodash/package.json"));
        Assert.DoesNotContain(result.Files, f => f.RelativePath.EndsWith("lodash.js"));
    }

    [Fact]
    public async Task Source_GitDirectory_IsSkipped()
    {
        var project = At("repo");
        Directory.CreateDirectory(Path.Combine(project, ".git"));
        File.WriteAllText(Path.Combine(project, ".git", "config"), "[core]");
        File.WriteAllText(Path.Combine(project, "app.py"), "print(1)");

        var result = await RecoverAsync(new SourceRecoveryBackend(), project);

        Assert.Contains(result.Files, f => f.RelativePath == "app.py");
        Assert.DoesNotContain(result.Files, f => f.RelativePath.StartsWith(".git/"));
    }

    [Fact]
    public async Task Source_ZippedProject_IsRead()
    {
        var zip = At("project.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            Write(archive, "package.json", "{\"name\":\"z\"}");
            Write(archive, "src/app.js", "console.log('hi');");
        }

        var result = await RecoverAsync(new SourceRecoveryBackend(), zip);

        Assert.Equal(2, result.Files.Count);
    }

    /// <summary>
    /// Entry names that traverse out of the archive root must never appear as recovered
    /// files, even though nothing is written to disk.
    /// </summary>
    [Fact]
    public async Task Source_ZipSlipEntry_IsRejected()
    {
        var zip = At("evil.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            Write(archive, "../../escaped.js", "pwned();");
            Write(archive, "safe.js", "ok();");
        }

        var result = await RecoverAsync(new SourceRecoveryBackend(), zip);

        Assert.DoesNotContain(result.Files, f => f.RelativePath.Contains(".."));
        Assert.Contains(result.Files, f => f.RelativePath == "safe.js");
        Assert.Contains(
            result.Coverage.ChecksNotPossible,
            w => w.Contains("unsafe path", StringComparison.Ordinal));
    }

    // ---- Native ------------------------------------------------------------

    [Fact]
    public async Task Native_ReportsZeroCoverageAndNamesWhatItCouldNotCheck()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(File.Exists(kernel32));

        var result = await RecoverAsync(new NativeRecoveryBackend(), kernel32);

        Assert.Empty(result.Files);
        Assert.Equal(0, result.Coverage.Percent);

        // A clean native result must never read as "nothing is wrong"; the report has to
        // enumerate what was out of reach.
        Assert.NotEmpty(result.Coverage.ChecksNotPossible);
        Assert.Contains(
            result.Coverage.ChecksNotPossible,
            c => c.Contains("credentials", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Native_MitigationFindingsAreBinaryHygieneOnly()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var result = await RecoverAsync(new NativeRecoveryBackend(), kernel32);

        Assert.All(result.Findings, f =>
            Assert.Equal(FindingCategory.BinaryHygiene, f.Category));
    }

    [Fact]
    public void Backends_ClaimDisjointArtifactKinds()
    {
        IRecoveryBackend[] backends =
        [
            new DotNetRecoveryBackend(),
            new ElectronRecoveryBackend(),
            new SourceRecoveryBackend(),
            new NativeRecoveryBackend(),
        ];

        foreach (var kind in Enum.GetValues<ArtifactKind>())
        {
            var claimants = backends.Count(b => b.CanHandle(kind));
            Assert.True(claimants <= 1, $"{kind} is claimed by {claimants} backends");
        }
    }

    private static void Write(ZipArchive archive, string path, string content)
    {
        using var stream = archive.CreateEntry(path).Open();
        using var writer = new StreamWriter(stream);
        writer.Write(content);
    }
}
