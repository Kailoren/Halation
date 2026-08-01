using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

public class DependencyInventoryTests
{
    private static DependencyInventoryResult Extract(params (string Path, string Content)[] files) =>
        DependencyInventory.Extract([.. files.Select(f => new RecoveredFile
        {
            RelativePath = f.Path,
            Content = f.Content,
            Language = RecoveredFile.LanguageOf(f.Path),
        })]);

    [Fact]
    public void DotNetDeps_CollectsPackagesButNotProjects()
    {
        var result = Extract(("MyApp.deps.json", """
            {
              "libraries": {
                "MyApp/1.0.0":            { "type": "project" },
                "Newtonsoft.Json/13.0.3": { "type": "package" },
                "Serilog/3.1.1":          { "type": "package" }
              }
            }
            """));

        Assert.Equal(2, result.Dependencies.Count);
        Assert.Contains(result.Dependencies, d => d.Coordinate == "NuGet:Newtonsoft.Json@13.0.3");
        Assert.Contains(result.Dependencies, d => d.Coordinate == "NuGet:Serilog@3.1.1");
        Assert.DoesNotContain(result.Dependencies, d => d.Name == "MyApp");
    }

    [Fact]
    public void DotNetDeps_HandlesDottedPackageNames()
    {
        var result = Extract(("app.deps.json", """
            {"libraries": {"System.Text.Encodings.Web/8.0.0": {"type": "package"}}}
            """));

        var dependency = Assert.Single(result.Dependencies);
        Assert.Equal("System.Text.Encodings.Web", dependency.Name);
        Assert.Equal("8.0.0", dependency.Version);
    }

    [Fact]
    public void NuGetLockFile_UsesResolvedVersions()
    {
        var result = Extract(("packages.lock.json", """
            {
              "version": 1,
              "dependencies": {
                "net8.0": {
                  "Polly":    { "type": "Direct",     "resolved": "8.2.0" },
                  "Serilog":  { "type": "Transitive", "resolved": "3.1.1" }
                }
              }
            }
            """));

        Assert.Equal(2, result.Dependencies.Count);
        Assert.All(result.Dependencies, d => Assert.Equal("NuGet", d.Ecosystem));
    }

    [Fact]
    public void NpmLockV3_ReadsFlatPackageMap()
    {
        var result = Extract(("package-lock.json", """
            {
              "lockfileVersion": 3,
              "packages": {
                "":                              { "name": "my-app", "version": "1.0.0" },
                "node_modules/lodash":           { "version": "4.17.20" },
                "node_modules/@babel/core":      { "version": "7.23.0" }
              }
            }
            """));

        Assert.Equal(2, result.Dependencies.Count);
        Assert.Contains(result.Dependencies, d => d.Coordinate == "npm:lodash@4.17.20");

        // Scoped packages keep their scope, which is part of the name OSV matches on.
        Assert.Contains(result.Dependencies, d => d.Coordinate == "npm:@babel/core@7.23.0");
    }

    [Fact]
    public void NpmLockV3_NestedPathsResolveToTheInnerPackageName()
    {
        var result = Extract(("package-lock.json", """
            {
              "lockfileVersion": 3,
              "packages": {
                "node_modules/foo/node_modules/bar": { "version": "2.0.0" }
              }
            }
            """));

        Assert.Equal("npm:bar@2.0.0", Assert.Single(result.Dependencies).Coordinate);
    }

    [Fact]
    public void NpmLockV1_ReadsNestedTree()
    {
        var result = Extract(("package-lock.json", """
            {
              "lockfileVersion": 1,
              "dependencies": {
                "express": {
                  "version": "4.17.1",
                  "dependencies": {
                    "cookie": { "version": "0.4.0" }
                  }
                }
              }
            }
            """));

        Assert.Contains(result.Dependencies, d => d.Coordinate == "npm:express@4.17.1");
        Assert.Contains(result.Dependencies, d => d.Coordinate == "npm:cookie@0.4.0");
    }

    [Fact]
    public void PinnedRequirements_AreCollected()
    {
        var result = Extract(("requirements.txt", """
            # comment
            requests==2.28.1
            urllib3[secure]==1.26.5

            -r other.txt
            """));

        Assert.Equal(2, result.Dependencies.Count);
        Assert.Contains(result.Dependencies, d => d.Coordinate == "PyPI:requests@2.28.1");
        Assert.Contains(result.Dependencies, d => d.Coordinate == "PyPI:urllib3@1.26.5");
    }

    /// <summary>
    /// A range cannot be matched against an advisory, because which version shipped depends
    /// on when the install ran. Guessing would produce findings wrong in both directions.
    /// </summary>
    [Theory]
    [InlineData("requests>=2.0.0")]
    [InlineData("django~=4.1")]
    [InlineData("flask")]
    public void UnpinnedRequirements_AreNotCollected(string line) =>
        Assert.Empty(Extract(("requirements.txt", line)).Dependencies);

    [Fact]
    public void PackageJsonAlone_IsReportedAsUnresolved()
    {
        var result = Extract(("package.json", """
            { "name": "app", "dependencies": { "lodash": "^4.17.0" } }
            """));

        Assert.Empty(result.Dependencies);
        Assert.Contains("package.json", result.Unresolved);
        Assert.Contains(result.Notes, n => n.Contains("ranges", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void LockFileBesidePackageJson_ResolvesTheVersions()
    {
        var result = Extract(
            ("package.json", """{ "dependencies": { "lodash": "^4.17.0" } }"""),
            ("package-lock.json", """
                {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.21"}}}
                """));

        Assert.Equal("npm:lodash@4.17.21", Assert.Single(result.Dependencies).Coordinate);
    }

    [Fact]
    public void DuplicatesAcrossManifests_AreCollapsed()
    {
        var result = Extract(
            ("a.deps.json", """{"libraries": {"Serilog/3.1.1": {"type": "package"}}}"""),
            ("b.deps.json", """{"libraries": {"Serilog/3.1.1": {"type": "package"}}}"""));

        Assert.Single(result.Dependencies);
    }

    [Fact]
    public void DifferentVersionsOfOnePackage_AreBothKept()
    {
        var result = Extract(("package-lock.json", """
            {
              "lockfileVersion": 3,
              "packages": {
                "node_modules/lodash":           { "version": "4.17.20" },
                "node_modules/a/node_modules/lodash": { "version": "3.10.1" }
              }
            }
            """));

        Assert.Equal(2, result.Dependencies.Count);
    }

    [Fact]
    public void MalformedManifest_IsNotedRatherThanThrowing()
    {
        var result = Extract(("MyApp.deps.json", "{ not json"));

        Assert.Empty(result.Dependencies);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void UnrelatedFiles_AreIgnored()
    {
        var result = Extract(
            ("src/app.js", "console.log(1);"),
            ("README.md", "# hello"));

        Assert.Empty(result.Dependencies);
        Assert.Empty(result.Notes);
    }

    [Fact]
    public void Results_AreDeterministicallyOrdered()
    {
        var manifest = ("app.deps.json", """
            {
              "libraries": {
                "Zed/1.0.0":   { "type": "package" },
                "Alpha/2.0.0": { "type": "package" },
                "Mid/3.0.0":   { "type": "package" }
              }
            }
            """);

        var first = Extract(manifest).Dependencies.Select(d => d.Coordinate);
        var second = Extract(manifest).Dependencies.Select(d => d.Coordinate);

        Assert.Equal(first, second);
        Assert.Equal(first.Order(StringComparer.Ordinal), first);
    }
}
