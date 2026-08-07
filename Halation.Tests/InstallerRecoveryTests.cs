using Halation.Core.Artifacts;
using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// What an installer gives up, per kind of payload it wraps.
/// </summary>
/// <remarks>
/// The installer is the shape almost everything arrives in, so a payload this backend declines
/// to open is a whole application unexamined. These tests exist to keep the three outcomes
/// distinguishable: read it, could not read it and said so, and never tried. The last of those
/// is the one that hid a gap for a while, because a .NET payload that was never handed to the
/// decompiler reported identically to a native one that could not be.
/// </remarks>
public class InstallerRecoveryTests
{
    private static async Task<RecoveryResult> RecoverAsync(byte[] payload, bool compress = true)
    {
        var path = TempFile(NsisBuilder.Build([NsisBuilder.Payload(payload, compress)]));

        try
        {
            var descriptor = ArtifactDetector.Detect(path);
            Assert.Equal(ArtifactKind.WindowsInstaller, descriptor.Kind);

            return await new InstallerRecoveryBackend().RecoverAsync(descriptor, CancellationToken.None);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// The gap this closed. VibeCheck decompiled a .NET assembly dropped in on its own from the
    /// first release, and reported the same assembly wrapped in an installer as holding nothing
    /// readable, which is the wrong answer given in the words of an honest one.
    /// </summary>
    [Fact]
    public async Task Decompiles_a_dotnet_assembly_packed_into_an_installer()
    {
        var assembly = await File.ReadAllBytesAsync(typeof(ScanReport).Assembly.Location);

        var result = await RecoverAsync(assembly);

        Assert.NotEmpty(result.Files);
        Assert.Contains(
            result.Files,
            f => f.RelativePath.EndsWith("ScoreCalculator.cs", StringComparison.Ordinal));

        // Recovered as decompiled source, not as bytes that happened to survive.
        Assert.All(result.Files, f => Assert.Equal(SourceLanguage.CSharp, f.Language));
        Assert.Contains("Calculate", string.Join("\n", result.Files.Select(f => f.Content)),
            StringComparison.Ordinal);

        Assert.True(result.Coverage.Percent > 0);
    }

    /// <summary>
    /// The same, through the other .NET shape: a single-file publish, where the application is
    /// a bundle appended to a native launcher rather than a loose assembly.
    /// </summary>
    [Fact]
    public async Task Unpacks_a_single_file_bundle_packed_into_an_installer()
    {
        var bundle = BundleBuilder.Build(
            ("myapp.deps.json", """{"runtimeTarget":{"name":".NETCoreApp,Version=v10.0"}}""",
                BundleFileType.DepsJson));

        // The reader reaches a payload by sniffing its first bytes, and a real bundle is
        // appended to a native launcher. The builder's stand-in launcher is zeroes, so it needs
        // the header a real one would have.
        "MZ"u8.CopyTo(bundle.AsSpan(0));

        var result = await RecoverAsync(bundle);

        var manifest = Assert.Single(result.Files);
        Assert.Equal("myapp.deps.json", manifest.RelativePath);
        Assert.Equal(SourceLanguage.Json, manifest.Language);
    }

    /// <summary>
    /// The path that carries most real installers, and the one the .NET work above had to leave
    /// exactly as it was. An electron-builder installer wraps its asar directly or inside a
    /// nested archive, and reading it is the difference between 285 application files and none.
    /// </summary>
    [Fact]
    public async Task Reads_an_electron_payload_packed_into_an_installer()
    {
        var asar = AsarBuilder.Build(
            ("app/main.js", "const { app } = require('electron');"),
            ("app/package.json", """{"name":"demo","version":"1.0.0"}"""));

        var result = await RecoverAsync(asar);

        Assert.Contains(result.Files, f => f.RelativePath.EndsWith("main.js", StringComparison.Ordinal));
        Assert.Contains("require('electron')", string.Join("\n", result.Files.Select(f => f.Content)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The outcome that must not change. A native payload cannot be decompiled by anybody, and
    /// the report has to say that rather than let it read as an application with nothing in it.
    /// </summary>
    [Fact]
    public async Task Reports_a_native_payload_as_unreadable_rather_than_empty()
    {
        var result = await RecoverAsync(NsisBuilder.MinimalPe());

        Assert.Empty(result.Files);
        Assert.Equal(0, result.Coverage.Percent);
        Assert.Contains(
            "readable application source",
            result.Coverage.Basis,
            StringComparison.Ordinal);

        // The installer script is never interpreted, so what it does during installation is
        // outside the scan and is stated in every installer report.
        Assert.Contains(
            result.Coverage.ChecksNotPossible,
            c => c.Contains("installer's own script", StringComparison.Ordinal));
    }

    /// <summary>
    /// Framework assemblies ship beside the application in a self-contained publish, one NSIS
    /// payload each. Decompiling them would bury the application's own code in thousands of
    /// files of somebody else's.
    /// </summary>
    [Fact]
    public async Task Skips_a_framework_assembly_shipped_beside_the_application()
    {
        var framework = await File.ReadAllBytesAsync(typeof(System.Text.Json.JsonDocument).Assembly.Location);

        var result = await RecoverAsync(framework);

        Assert.Empty(result.Files);
    }

    private static string TempFile(byte[] content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"halation-installer-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, content);

        return path;
    }
}
