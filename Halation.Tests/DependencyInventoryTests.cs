using Halation.Core.Dependencies;
using Halation.Core.Recovery;

namespace Halation.Tests;

public class DependencyInventoryTests
{
    private static DependencyInventoryResult Extract(params (string Path, string Content)[] files) =>
        DependencyInventory.Extract([.. files.Select(f => new RecoveredFile
        {
            RelativePath = f.Path,
            Content = f.Content,
            Language = RecoveredFile.LanguageOf(f.Path),
        })]);

    private static string Manifest(string name, string version) =>
        $$"""{"name":"{{name}}","version":"{{version}}"}""";

    [Fact]
    public void Vendored_manifest_resolves_to_an_exact_package()
    {
        var result = Extract(
            ("node_modules/lodash/package.json", Manifest("lodash", "4.17.21")));

        var dependency = Assert.Single(result.Dependencies);
        Assert.Equal("npm:lodash@4.17.21", dependency.Coordinate);
    }

    /// <summary>
    /// The application's own manifest declares ranges and says nothing about what shipped,
    /// so it must keep counting as unresolved rather than being read as a dependency.
    /// </summary>
    [Fact]
    public void Root_manifest_is_still_unresolved_and_is_not_a_dependency()
    {
        var result = Extract(
            ("package.json", """{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"""));

        Assert.Empty(result.Dependencies);
        Assert.Equal(["package.json"], result.Unresolved);
    }

    /// <summary>
    /// A vendored manifest's ranges are covered by the packages themselves, which are all
    /// present with exact versions. Counting them resolved 149 packages in a real
    /// application and then reported the same 149 as unchecked.
    /// </summary>
    [Fact]
    public void Vendored_manifest_ranges_are_not_reported_as_unresolved()
    {
        var result = Extract(
            ("node_modules/express/package.json",
                """{"name":"express","version":"4.18.2","dependencies":{"accepts":"~1.3.8"}}"""));

        Assert.Single(result.Dependencies);
        Assert.Empty(result.Unresolved);
    }

    [Fact]
    public void Scoped_package_keeps_its_scope()
    {
        var result = Extract(
            ("node_modules/@babel/runtime/package.json", Manifest("@babel/runtime", "7.24.0")));

        var dependency = Assert.Single(result.Dependencies);
        Assert.Equal("npm:@babel/runtime@7.24.0", dependency.Coordinate);
    }

    [Fact]
    public void Nested_dependency_resolves_under_its_own_name()
    {
        var result = Extract(
            ("node_modules/a/node_modules/b/package.json", Manifest("b", "2.0.0")));

        var dependency = Assert.Single(result.Dependencies);
        Assert.Equal("npm:b@2.0.0", dependency.Coordinate);
    }

    /// <summary>
    /// This is untrusted input, and a range reaching OSV would be matched as though it were
    /// an exact version.
    /// </summary>
    [Theory]
    [InlineData("^4.17.0")]
    [InlineData("~1.2.3")]
    [InlineData(">=1.0.0")]
    [InlineData("*")]
    [InlineData("1.0.0 || 2.0.0")]
    [InlineData("latest")]
    public void Range_valued_version_is_rejected(string version)
    {
        var result = Extract(("node_modules/x/package.json", Manifest("x", version)));

        Assert.Empty(result.Dependencies);
    }

    /// <summary>
    /// Packages ship internal manifests in subdirectories. One real application vendors
    /// node_modules/fast-uri/benchmark/package.json, whose declared name is "benchmark", a
    /// real npm package the application does not ship. Trusting the name alone would report
    /// a vulnerability in something that is not there.
    /// </summary>
    [Fact]
    public void Manifest_in_a_package_subdirectory_is_not_treated_as_an_installed_package()
    {
        var result = Extract(
            ("node_modules/fast-uri/benchmark/package.json", Manifest("benchmark", "2.1.4")));

        Assert.Empty(result.Dependencies);
    }

    /// <summary>Subdirectory marker manifests carry neither a name nor a version.</summary>
    [Fact]
    public void Manifest_without_a_name_or_version_is_skipped()
    {
        var result = Extract(
            ("node_modules/pkg/dist/package.json", """{"type":"module"}"""));

        Assert.Empty(result.Dependencies);
    }

    [Fact]
    public void Bundled_packages_carry_a_note_about_what_the_list_means()
    {
        var result = Extract(
            ("node_modules/lodash/package.json", Manifest("lodash", "4.17.21")));

        Assert.Contains(result.Notes, n => n.Contains("ships rather than what it loads", StringComparison.Ordinal));
        Assert.Contains(result.Notes, n => n.Contains("asarUnpack", StringComparison.Ordinal));
    }

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
