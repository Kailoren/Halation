using System.IO.Compression;
using System.Text;

using Halation.Core.Artifacts;
using Halation.Core.Model;

namespace Halation.Tests;

public class ArtifactDetectorTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("halation-tests-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    private string Path(string name) => System.IO.Path.Combine(_scratch, name);

    /// <summary>
    /// Uses this test assembly itself, so the managed-PE path is exercised against a real
    /// compiler-produced binary rather than a hand-built header.
    /// </summary>
    [Fact]
    public void ManagedAssembly_DetectedAsDotNet()
    {
        var self = typeof(ArtifactDetectorTests).Assembly.Location;

        var result = ArtifactDetector.Detect(self);

        Assert.Equal(ArtifactKind.DotNetAssembly, result.Kind);
        Assert.False(result.IsDirectory);
        Assert.True(result.Bytes > 0);
    }

    [Fact]
    public void NativeBinary_DetectedAsNative()
    {
        // Halation targets Windows, so kernel32.dll is a dependable native-PE fixture.
        var kernel32 = System.IO.Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(File.Exists(kernel32), $"expected a native PE fixture at {kernel32}");

        var result = ArtifactDetector.Detect(kernel32);

        Assert.Equal(ArtifactKind.NativeWindows, result.Kind);
    }

    [Fact]
    public void ExtensionIsIgnored_ContentDecides()
    {
        // An untrusted download is exactly where the extension is least trustworthy.
        var disguised = Path("totally-a-picture.png");
        File.Copy(typeof(ArtifactDetectorTests).Assembly.Location, disguised);

        var result = ArtifactDetector.Detect(disguised);

        Assert.Equal(ArtifactKind.DotNetAssembly, result.Kind);
    }

    [Fact]
    public void ZipWithManifest_DetectedAsJavaArchive()
    {
        var jar = Path("app.jar");
        using (var archive = ZipFile.Open(jar, ZipArchiveMode.Create))
        {
            archive.CreateEntry("META-INF/MANIFEST.MF");
            archive.CreateEntry("com/example/Main.class");
        }

        Assert.Equal(ArtifactKind.JavaArchive, ArtifactDetector.Detect(jar).Kind);
    }

    [Fact]
    public void ZipWithPackageJson_DetectedAsSourceTree()
    {
        var zip = Path("project.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntry("package.json");
            archive.CreateEntry("src/index.js");
        }

        Assert.Equal(ArtifactKind.SourceTree, ArtifactDetector.Detect(zip).Kind);
    }

    [Fact]
    public void ZipWithAsar_DetectedAsElectronApp()
    {
        var zip = Path("electron-app.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntry("MyApp/resources/app.asar");
            archive.CreateEntry("MyApp/MyApp.exe");
        }

        Assert.Equal(ArtifactKind.ElectronApp, ArtifactDetector.Detect(zip).Kind);
    }

    [Fact]
    public void PlainZip_DetectedAsArchive()
    {
        var zip = Path("stuff.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntry("notes.txt");
        }

        Assert.Equal(ArtifactKind.Archive, ArtifactDetector.Detect(zip).Kind);
    }

    [Fact]
    public void BareAsar_DetectedByHeaderSignature()
    {
        var asar = Path("app.asar");
        File.WriteAllBytes(asar, AsarBuilder.MinimalHeader());

        Assert.Equal(ArtifactKind.AsarArchive, ArtifactDetector.Detect(asar).Kind);
    }

    [Fact]
    public void DirectoryWithAsar_DetectedAsElectronApp()
    {
        var app = Path("InstalledApp");
        Directory.CreateDirectory(System.IO.Path.Combine(app, "resources"));
        File.WriteAllBytes(System.IO.Path.Combine(app, "resources", "app.asar"),
            AsarBuilder.MinimalHeader());

        var result = ArtifactDetector.Detect(app);

        Assert.Equal(ArtifactKind.ElectronApp, result.Kind);
        Assert.True(result.IsDirectory);
    }

    [Fact]
    public void DirectoryWithPackageJson_DetectedAsSourceTree()
    {
        var project = Path("my-project");
        Directory.CreateDirectory(project);
        File.WriteAllText(System.IO.Path.Combine(project, "package.json"), "{}");

        Assert.Equal(ArtifactKind.SourceTree, ArtifactDetector.Detect(project).Kind);
    }

    [Fact]
    public void ElfBinary_ReportedAsUnsupportedRatherThanClean()
    {
        // The honest outcome for an artifact this build cannot read is "not analysable",
        // never a clean result.
        var elf = Path("binary");
        File.WriteAllBytes(elf, [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);

        var result = ArtifactDetector.Detect(elf);

        Assert.Equal(ArtifactKind.Unknown, result.Kind);
        Assert.Contains("ELF", result.Detail);
    }

    [Fact]
    public void TruncatedPe_DoesNotThrow()
    {
        var broken = Path("truncated.exe");
        File.WriteAllBytes(broken, Encoding.ASCII.GetBytes("MZ").Concat(new byte[40]).ToArray());

        var result = ArtifactDetector.Detect(broken);

        Assert.Equal(ArtifactKind.Unknown, result.Kind);
    }

    [Fact]
    public void MissingPath_Throws()
    {
        Assert.Throws<FileNotFoundException>(
            () => ArtifactDetector.Detect(Path("does-not-exist.exe")));
    }

    [Fact]
    public void Sha256_IsStableAndChangesWithContent()
    {
        var a = Path("a.txt");
        var b = Path("b.txt");
        File.WriteAllText(a, "hello");
        File.WriteAllText(b, "hello!");

        var hashA1 = ArtifactDetector.ComputeSha256(ArtifactDetector.Detect(a));
        var hashA2 = ArtifactDetector.ComputeSha256(ArtifactDetector.Detect(a));
        var hashB = ArtifactDetector.ComputeSha256(ArtifactDetector.Detect(b));

        Assert.Equal(hashA1, hashA2);
        Assert.NotEqual(hashA1, hashB);
        Assert.Equal(64, hashA1.Length);
    }
}
