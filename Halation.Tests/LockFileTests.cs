using Halation.Core.Dependencies;
using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Lock files from the ecosystems beyond npm, NuGet and PyPI.
/// </summary>
/// <remarks>
/// A lock file is the only artifact that says what a project actually installed rather than
/// what it asked for, so each one added here is the difference between a whole language's
/// dependencies being checkable and being invisible. Verified live against OSV when written:
/// every fixture below returns real advisories.
/// </remarks>
public class LockFileTests
{
    private static IReadOnlyList<DependencyRef> Read(string name, string content) =>
        DependencyInventory.Extract(
        [
            new RecoveredFile
            {
                RelativePath = name,
                Content = content,
                Language = SourceLanguage.Config,
            },
        ]).Dependencies;

    // ---- npm, the two formats that are not package-lock -----------------------

    /// <summary>
    /// Classic Yarn. Several specifiers can share one entry, and they resolve to the same
    /// package, so the first names it.
    /// </summary>
    [Fact]
    public void YarnLock_classic_reads_the_resolved_version()
    {
        var found = Read("yarn.lock", """
            # yarn lockfile v1

            lodash@^4.17.20:
              version "4.17.21"
              resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"

            "@babel/core@^7.0.0", "@babel/core@^7.12.0":
              version "7.14.0"
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("npm", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "lodash" && d.Version == "4.17.21");

        // The separator is the last @, not the first, or a scoped package loses its scope.
        Assert.Contains(found, d => d.Name == "@babel/core" && d.Version == "7.14.0");
    }

    /// <summary>Berry writes YAML. Same shape, different punctuation.</summary>
    [Fact]
    public void YarnLock_berry_reads_the_resolved_version()
    {
        var found = Read("yarn.lock", """
            "lodash@npm:^4.17.20":
              version: 4.17.21
              resolution: "lodash@npm:4.17.21"

            "@babel/core@npm:^7.0.0":
              version: 7.14.0
            """);

        Assert.Equal(2, found.Count);
        Assert.Contains(found, d => d.Name == "lodash" && d.Version == "4.17.21");
        Assert.Contains(found, d => d.Name == "@babel/core" && d.Version == "7.14.0");
    }

    /// <summary>
    /// pnpm keys the record by the package itself, and has spelled that four ways across its
    /// versions. A project's lock file is whichever pnpm wrote it.
    /// </summary>
    [Theory]
    [InlineData("  /lodash/4.17.21:", "lodash", "4.17.21")]
    [InlineData("  /@babel/core/7.14.0:", "@babel/core", "7.14.0")]
    [InlineData("  /lodash@4.17.21:", "lodash", "4.17.21")]
    [InlineData("  /@babel/core@7.14.0:", "@babel/core", "7.14.0")]
    [InlineData("  lodash@4.17.21:", "lodash", "4.17.21")]
    [InlineData("  '@babel/core@7.14.0':", "@babel/core", "7.14.0")]

    // Peer suffixes say how it was built, not what it is.
    [InlineData("  react-dom@18.2.0(react@18.2.0):", "react-dom", "18.2.0")]
    public void PnpmLock_reads_every_spelling_of_the_key(string key, string name, string version)
    {
        var dependency = Assert.Single(Read("pnpm-lock.yaml", $"packages:\n{key}\n    resolution: {{integrity: sha512-x}}\n"));

        Assert.Equal("npm", dependency.Ecosystem);
        Assert.Equal(name, dependency.Name);
        Assert.Equal(version, dependency.Version);
    }

    /// <summary>
    /// Later pnpm repeats the whole list under <c>snapshots</c>. Reading both would double
    /// every package in the report.
    /// </summary>
    [Fact]
    public void PnpmLock_reads_the_packages_section_only()
    {
        var found = Read("pnpm-lock.yaml", """
            lockfileVersion: '9.0'

            packages:
              lodash@4.17.21:
                resolution: {integrity: sha512-x}

            snapshots:
              lodash@4.17.21: {}
            """);

        Assert.Single(found);
    }

    /// <summary>A property of a package is not another package, however deeply it is nested.</summary>
    [Fact]
    public void PnpmLock_ignores_nested_properties()
    {
        var found = Read("pnpm-lock.yaml", """
            packages:
              lodash@4.17.21:
                resolution: {integrity: sha512-x}
                engines: {node: '>=12'}
                dependencies:
                  something@1.0.0: {}
            """);

        Assert.Equal("lodash", Assert.Single(found).Name);
    }

    // ---- Python, beyond requirements.txt --------------------------------------

    /// <summary>
    /// Pipenv writes requirement specifiers, so an exact pin arrives as "==2.25.1". Anything
    /// looser names no version that can be checked.
    /// </summary>
    [Fact]
    public void PipfileLock_reads_exact_pins_from_both_sections()
    {
        var found = Read("Pipfile.lock", """
            {
              "_meta": { "hash": { "sha256": "abc" } },
              "default": {
                "requests": { "version": "==2.25.1" },
                "urllib3":  { "version": ">=1.26" },
                "internal": { "git": "https://example.com/repo.git", "ref": "abc123" }
              },
              "develop": {
                "pytest": { "version": "==6.2.2" }
              }
            }
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("PyPI", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "requests" && d.Version == "2.25.1");
        Assert.Contains(found, d => d.Name == "pytest" && d.Version == "6.2.2");

        // A range and a git reference both leave the installed version undetermined.
        Assert.DoesNotContain(found, d => d.Name is "urllib3" or "internal");
    }

    /// <summary>The metadata block is not a package list, whatever it happens to contain.</summary>
    [Fact]
    public void PipfileLock_does_not_read_the_meta_section() =>
        Assert.Empty(Read(
            "Pipfile.lock",
            """{ "_meta": { "requires": { "version": "==3.9" } } }"""));

    // ---- Go ------------------------------------------------------------------

    /// <summary>
    /// Every module appears twice in a go.sum: once for its code and once for its manifest.
    /// Reading both would double the list and query a version that is not a package.
    /// </summary>
    [Fact]
    public void GoSum_reads_modules_once_and_drops_the_go_mod_lines()
    {
        var found = Read("go.sum", """
            github.com/gogo/protobuf v1.3.1 h1:abc=
            github.com/gogo/protobuf v1.3.1/go.mod h1:def=
            github.com/gin-gonic/gin v1.6.3 h1:ghi=
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("Go", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "github.com/gin-gonic/gin" && d.Version == "1.6.3");
    }

    /// <summary>
    /// Go writes <c>v1.2.3</c> and OSV indexes <c>1.2.3</c>. Sent unstripped, every query
    /// returns nothing and the report calls a vulnerable module clean.
    /// </summary>
    [Fact]
    public void GoSum_strips_the_version_prefix() =>
        Assert.Equal(
            "1.3.1",
            Assert.Single(Read("go.sum", "github.com/gogo/protobuf v1.3.1 h1:abc=")).Version);

    // ---- Rust and Python -----------------------------------------------------

    [Fact]
    public void CargoLock_reads_each_package_table()
    {
        var found = Read("Cargo.lock", """
            [[package]]
            name = "smallvec"
            version = "0.6.13"

            [[package]]
            name = "time"
            version = "0.1.43"
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("crates.io", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "smallvec" && d.Version == "0.6.13");
    }

    /// <summary>Same file shape, different ecosystem, so one reader serves both.</summary>
    [Fact]
    public void PoetryLock_reads_as_pypi()
    {
        var found = Read("poetry.lock", """
            [[package]]
            name = "jinja2"
            version = "2.11.2"
            """);

        Assert.Equal("PyPI", Assert.Single(found).Ecosystem);
    }

    /// <summary>
    /// A table with a name and no version must not borrow the next table's, which is what
    /// happens if the reader keeps state across the table boundary.
    /// </summary>
    [Fact]
    public void CargoLock_does_not_carry_a_name_into_the_next_table()
    {
        var found = Read("Cargo.lock", """
            [[package]]
            name = "no-version-here"

            [[package]]
            name = "time"
            version = "0.1.43"
            """);

        Assert.Equal("time", Assert.Single(found).Name);
    }

    // ---- PHP -----------------------------------------------------------------

    [Fact]
    public void ComposerLock_reads_both_sets_and_strips_the_prefix()
    {
        var found = Read(
            "composer.lock",
            """
            {
              "packages": [ { "name": "guzzlehttp/guzzle", "version": "6.5.0" } ],
              "packages-dev": [ { "name": "phpunit/phpunit", "version": "v8.5.1" } ]
            }
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("Packagist", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "phpunit/phpunit" && d.Version == "8.5.1");
    }

    // ---- Ruby ----------------------------------------------------------------

    /// <summary>
    /// Indentation is the meaning. A gem sits at four spaces; the requirements it declares sit
    /// at six, as ranges. Reading both reports "~&gt; 2.4.0" as an installed version.
    /// </summary>
    [Fact]
    public void GemfileLock_reads_installs_and_not_requirements()
    {
        var found = Read("Gemfile.lock", """
            GEM
              remote: https://rubygems.org/
              specs:
                nokogiri (1.10.4)
                  mini_portile2 (~> 2.4.0)
                rack (2.0.7)

            PLATFORMS
              ruby
            """);

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.Equal("RubyGems", d.Ecosystem));
        Assert.Contains(found, d => d.Name == "nokogiri" && d.Version == "1.10.4");
        Assert.DoesNotContain(found, d => d.Name == "mini_portile2");
    }

    // ---- Java ----------------------------------------------------------------

    /// <summary>OSV names a Maven package by group and artifact together.</summary>
    [Fact]
    public void GradleLockfile_joins_the_group_to_the_artifact()
    {
        var found = Read("gradle.lockfile", """
            # This is a Gradle generated file for dependency locking.
            org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
            empty=classpath
            """);

        var dependency = Assert.Single(found);

        Assert.Equal("Maven", dependency.Ecosystem);
        Assert.Equal("org.apache.logging.log4j:log4j-core", dependency.Name);
        Assert.Equal("2.14.1", dependency.Version);
    }

    // ---- Across the set ------------------------------------------------------

    /// <summary>
    /// The ecosystem strings are what OSV matches on. A typo in one of them is silent: the
    /// query returns nothing and the packages are reported clean.
    /// </summary>
    [Fact]
    public void Every_ecosystem_name_is_one_osv_publishes_under()
    {
        string[] known =
        [
            "npm", "NuGet", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven",
        ];

        var found = Read("go.sum", "github.com/gin-gonic/gin v1.6.3 h1:abc=")
            .Concat(Read("Cargo.lock", "[[package]]\nname = \"time\"\nversion = \"0.1.43\""))
            .Concat(Read("Gemfile.lock", "GEM\n  specs:\n    rack (2.0.7)\n"))
            .Concat(Read("gradle.lockfile", "g:a:1.0=classpath"))
            .Concat(Read(
                "composer.lock",
                """{ "packages": [ { "name": "a/b", "version": "1.0" } ] }"""));

        Assert.NotEmpty(found);
        Assert.All(found, d => Assert.Contains(d.Ecosystem, known));
    }

    /// <summary>A malformed lock file is skipped, never thrown out of a scan.</summary>
    [Theory]
    [InlineData("go.sum", "not a checksum line")]
    [InlineData("Cargo.lock", "[[package]]\nnothing here")]
    [InlineData("Gemfile.lock", "GEM\n  specs:\n    malformed line without parens\n")]
    [InlineData("gradle.lockfile", "=\n:::\n")]
    public void A_malformed_lock_file_yields_nothing_rather_than_failing(string name, string content) =>
        Assert.Empty(Read(name, content));
}
