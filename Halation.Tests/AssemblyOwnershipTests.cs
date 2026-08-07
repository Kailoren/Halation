using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Covers separating an application's own assemblies from the dependencies it ships.
/// </summary>
/// <remarks>
/// Measured against three third-party applications, this removed 78% of findings, all of
/// them in other people's libraries. One went from 48 findings to 2 once SharpDX interop and
/// SharpZipLib constants stopped being attributed to it.
/// </remarks>
public class AssemblyOwnershipTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-owner-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    private const string DepsJson = """
        {
          "runtimeTarget": { "name": ".NETCoreApp,Version=v8.0" },
          "libraries": {
            "MyApp/1.0.0":            { "type": "project" },
            "MyApp.Core/1.0.0":       { "type": "project" },
            "Newtonsoft.Json/13.0.3": { "type": "package" },
            "SharpDX/4.2.0":          { "type": "package" }
          }
        }
        """;

    [Fact]
    public void DependencyManifest_IdentifiesProjectAssemblies()
    {
        var ownership = AssemblyOwnership.FromDepsJson(DepsJson);

        Assert.NotNull(ownership);
        Assert.True(ownership.IsApplicationCode("MyApp.dll"));
        Assert.True(ownership.IsApplicationCode("MyApp.Core.dll"));
        Assert.False(ownership.IsApplicationCode("Newtonsoft.Json.dll"));
        Assert.False(ownership.IsApplicationCode("SharpDX.dll"));
    }

    /// <summary>
    /// A manifest is read from the build, so the separation it gives is exact and the report
    /// should not hedge about it.
    /// </summary>
    [Fact]
    public void DependencyManifest_IsNotApproximate()
    {
        var ownership = AssemblyOwnership.FromDepsJson(DepsJson);

        Assert.NotNull(ownership);
        Assert.False(ownership.IsApproximate);
        Assert.Contains("manifest", ownership.Method, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("""{"libraries":{}}""")]
    [InlineData("""{"libraries":{"OnlyPackages/1.0.0":{"type":"package"}}}""")]
    public void UnusableManifest_FallsThroughRatherThanThrowing(string json) =>
        Assert.Null(AssemblyOwnership.FromDepsJson(json));

    [Fact]
    public void FrameworkAssemblies_AreNeverApplicationCode()
    {
        var ownership = AssemblyOwnership.FromDepsJson(DepsJson);

        Assert.NotNull(ownership);
        Assert.False(ownership.IsApplicationCode("System.Text.Json.dll"));
        Assert.False(ownership.IsApplicationCode("PresentationCore.dll"));
    }

    [Fact]
    public void WithoutAManifest_KnownPackagesAreStillExcluded()
    {
        var ownership = AssemblyOwnership.VendorList;

        Assert.False(ownership.IsApplicationCode("SharpDX.DXGI.dll"));
        Assert.False(ownership.IsApplicationCode("NetMQ.dll"));
        Assert.False(ownership.IsApplicationCode("Google.Protobuf.dll"));
        Assert.False(ownership.IsApplicationCode("ICSharpCode.SharpZipLib.dll"));

        // An unrecognised name is treated as the application's, so an unknown package costs
        // noise rather than silently hiding the app.
        Assert.True(ownership.IsApplicationCode("EliteDangerousCore.dll"));
        Assert.True(ownership.IsApplicationCode("SomeObscureLibrary.dll"));
    }

    [Fact]
    public void ManifestOnDisk_IsPreferredOverHeuristics()
    {
        var app = Path.Combine(_scratch, "published");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "MyApp.deps.json"), DepsJson);

        var ownership = AssemblyOwnership.ForDirectory(app);

        Assert.False(ownership.IsApproximate);
        Assert.True(ownership.IsApplicationCode("MyApp.dll"));
        Assert.False(ownership.IsApplicationCode("SharpDX.dll"));
    }

    /// <summary>
    /// Build output ships symbols and restored packages generally do not, which is the only
    /// signal available for a .NET Framework application with no manifest.
    /// </summary>
    [Fact]
    public void WithoutAManifest_SymbolsIdentifyApplicationAssemblies()
    {
        var app = Path.Combine(_scratch, "framework-app");
        Directory.CreateDirectory(app);

        foreach (var name in new[] { "AppCore", "AppUi", "AppData", "AppPlugins" })
        {
            File.WriteAllText(Path.Combine(app, $"{name}.pdb"), "symbols");
        }

        var ownership = AssemblyOwnership.ForDirectory(app);

        Assert.True(ownership.IsApproximate);
        Assert.True(ownership.IsApplicationCode("AppCore.dll"));
        Assert.False(ownership.IsApplicationCode("SomeDependency.dll"));
    }

    /// <summary>
    /// Some distributions ship symbols for their dependencies too. OpenTK and AsyncIO both
    /// arrived with a .pdb and were attributed to the application until the name check was
    /// applied alongside the symbol match rather than only as a fallback.
    /// </summary>
    [Fact]
    public void SymbolsForAKnownPackage_DoNotMakeItApplicationCode()
    {
        var app = Path.Combine(_scratch, "with-vendor-symbols");
        Directory.CreateDirectory(app);

        foreach (var name in new[] { "AppCore", "AppUi", "AppData", "OpenTK", "AsyncIO" })
        {
            File.WriteAllText(Path.Combine(app, $"{name}.pdb"), "symbols");
        }

        var ownership = AssemblyOwnership.ForDirectory(app);

        Assert.True(ownership.IsApplicationCode("AppCore.dll"));
        Assert.False(ownership.IsApplicationCode("OpenTK.dll"));
        Assert.False(ownership.IsApplicationCode("AsyncIO.dll"));
    }

    [Fact]
    public void OneStraySymbolFile_DoesNotExcludeEverythingElse()
    {
        var app = Path.Combine(_scratch, "one-pdb");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "Stray.pdb"), "symbols");

        var ownership = AssemblyOwnership.ForDirectory(app);

        // Too few symbols to look like build output, so it must not conclude that the single
        // named assembly is the entire application.
        Assert.True(ownership.IsApplicationCode("MainApplication.dll"));
    }
}
