using Halation.Core.DeepPass;

namespace Halation.Tests;

/// <summary>
/// Finding the CLI is the whole of whether the deep pass is available to somebody who has not
/// bought an API key, so the search is tested against laid-out directories rather than against
/// whatever happens to be installed on the machine running the tests.
/// </summary>
public sealed class ClaudeCodeCliLocatorTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(), "halation-cli-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leaked temp directory is not worth failing a test run over.
        }
    }

    /// <summary>Creates an empty file at a path under the temp root. Never executed.</summary>
    private string Touch(params string[] parts)
    {
        var path = Path.Combine([_root, .. parts]);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, string.Empty);
        return path;
    }

    private string Dir(params string[] parts) => Path.Combine([_root, .. parts]);

    /// <summary>A probe whose every root is inside the temp directory, so nothing real is found.</summary>
    private ClaudeCodeCliProbe Probe(params string[] pathDirectories) => new()
    {
        ExecutableDirectories = pathDirectories.Select(d => Dir(d)).ToList(),
        ApplicationData = Dir("AppData", "Roaming"),
        LocalApplicationData = Dir("AppData", "Local"),
        UserProfile = Dir("Home"),
    };

    // ---- Nothing installed -------------------------------------------------

    [Fact]
    public void Finds_nothing_when_no_location_holds_an_executable() =>
        Assert.Null(ClaudeCodeCliLocator.Locate(Probe()));

    [Fact]
    public void Tolerates_roots_that_do_not_exist() =>
        Assert.Null(ClaudeCodeCliLocator.Locate(new ClaudeCodeCliProbe
        {
            ExecutableDirectories = [Dir("nope")],
            ApplicationData = Dir("also-nope"),
            LocalApplicationData = Dir("still-nope"),
            UserProfile = Dir("never"),
        }));

    [Fact]
    public void Tolerates_a_probe_with_nothing_set_at_all() =>
        Assert.Null(ClaudeCodeCliLocator.Locate(new ClaudeCodeCliProbe()));

    // ---- The packaged desktop app ------------------------------------------

    /// <summary>
    /// The case this class exists for. When the desktop app is a packaged (MSIX) install, its
    /// bundled CLI is not visible at the roaming path a process inside that package sees. An
    /// unpackaged application has to look under the package's own storage or it finds nothing.
    /// </summary>
    [Fact]
    public void Finds_the_cli_bundled_inside_a_packaged_desktop_app()
    {
        var expected = Touch(
            "AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc",
            "LocalCache", "Roaming", "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(expected, found.Path);
        Assert.Equal(ClaudeCodeCliSource.PackagedDesktopApp, found.Source);
        Assert.Equal(new Version(2, 1, 219), found.Version);
    }

    /// <summary>
    /// The publisher suffix differs between signing channels, so it is matched rather than
    /// assumed. A hardcoded family name would work on one machine and silently fail elsewhere.
    /// </summary>
    [Fact]
    public void Finds_a_packaged_app_under_a_different_publisher_suffix()
    {
        Touch("AppData", "Local", "Packages", "Claude_somethingelse99",
              "LocalCache", "Roaming", "Claude", "claude-code", "3.0.1", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(ClaudeCodeCliSource.PackagedDesktopApp, found.Source);
    }

    /// <summary>Packages belonging to other applications are not mistaken for this one.</summary>
    [Fact]
    public void Ignores_unrelated_packages()
    {
        Touch("AppData", "Local", "Packages", "SomethingElse_abc",
              "LocalCache", "Roaming", "Claude", "claude-code", "1.0.0", "claude.exe");

        Assert.Null(ClaudeCodeCliLocator.Locate(Probe()));
    }

    // ---- Version ordering --------------------------------------------------

    /// <summary>
    /// The regression that a string sort causes and a version sort does not. "2.1.99" sorts
    /// above "2.1.219" as text, which would pin a machine to an install hundreds of releases
    /// behind the one it actually has.
    /// </summary>
    [Fact]
    public void Prefers_the_numerically_highest_version_not_the_alphabetically_highest()
    {
        var stale = Touch("AppData", "Roaming", "Claude", "claude-code", "2.1.99", "claude.exe");
        var current = Touch("AppData", "Roaming", "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(current, found.Path);
        Assert.NotEqual(stale, found.Path);
        Assert.Equal(new Version(2, 1, 219), found.Version);
    }

    /// <summary>
    /// A directory whose name is not a version still counts, but only once every real version
    /// has been ruled out. An unfamiliar naming scheme should cost precedence, not the install.
    /// </summary>
    [Fact]
    public void Prefers_a_parsable_version_over_an_unparsable_directory_name()
    {
        Touch("AppData", "Roaming", "Claude", "claude-code", "nightly", "claude.exe");
        var versioned = Touch("AppData", "Roaming", "Claude", "claude-code", "1.0.0", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(versioned, found.Path);
    }

    [Fact]
    public void Still_finds_an_install_whose_directory_name_is_not_a_version()
    {
        var only = Touch("AppData", "Roaming", "Claude", "claude-code", "nightly", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(only, found.Path);
        Assert.Null(found.Version);
    }

    /// <summary>A version directory that holds no executable must not stop the search.</summary>
    [Fact]
    public void Skips_a_version_directory_with_no_executable_in_it()
    {
        Directory.CreateDirectory(Dir("AppData", "Roaming", "Claude", "claude-code", "9.9.9"));
        var real = Touch("AppData", "Roaming", "Claude", "claude-code", "1.0.0", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(real, found.Path);
    }

    // ---- Precedence between locations --------------------------------------

    [Fact]
    public void Prefers_an_executable_on_path_above_everything_else()
    {
        var onPath = Touch("bin", "claude.exe");
        Touch("AppData", "Roaming", "npm", "claude.cmd");
        Touch("Home", ".local", "bin", "claude.exe");
        Touch("AppData", "Local", "Packages", "Claude_x", "LocalCache", "Roaming",
              "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe("bin"));

        Assert.NotNull(found);
        Assert.Equal(onPath, found.Path);
        Assert.Equal(ClaudeCodeCliSource.Path, found.Source);
    }

    [Fact]
    public void Falls_back_to_the_npm_global_directory()
    {
        var npm = Touch("AppData", "Roaming", "npm", "claude.cmd");

        var found = ClaudeCodeCliLocator.Locate(Probe("bin"));

        Assert.NotNull(found);
        Assert.Equal(npm, found.Path);
        Assert.Equal(ClaudeCodeCliSource.NpmGlobal, found.Source);
    }

    [Fact]
    public void Falls_back_to_the_native_installer_location()
    {
        var native = Touch("Home", ".local", "bin", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(native, found.Path);
        Assert.Equal(ClaudeCodeCliSource.NativeInstaller, found.Source);
    }

    /// <summary>
    /// A standalone install wins over the bundled copy even though both work, because the
    /// bundled one lives in another application's private storage under a directory that
    /// moves every time that application updates.
    /// </summary>
    [Fact]
    public void Prefers_a_standalone_install_over_the_bundled_copy()
    {
        var native = Touch("Home", ".local", "bin", "claude.exe");
        Touch("AppData", "Local", "Packages", "Claude_x", "LocalCache", "Roaming",
              "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(native, found.Path);
    }

    /// <summary>
    /// The packaged location is searched before the plain roaming one. Both can exist on a
    /// machine that has had the app installed both ways, and the packaged copy is the one a
    /// current install maintains.
    /// </summary>
    [Fact]
    public void Prefers_the_packaged_location_over_the_unpackaged_one()
    {
        var packaged = Touch("AppData", "Local", "Packages", "Claude_x", "LocalCache", "Roaming",
                             "Claude", "claude-code", "2.1.219", "claude.exe");
        Touch("AppData", "Roaming", "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(packaged, found.Path);
        Assert.Equal(ClaudeCodeCliSource.PackagedDesktopApp, found.Source);
    }

    [Fact]
    public void Finds_the_cli_bundled_with_an_unpackaged_desktop_app()
    {
        var expected = Touch("AppData", "Roaming", "Claude", "claude-code", "2.1.219", "claude.exe");

        var found = ClaudeCodeCliLocator.Locate(Probe());

        Assert.NotNull(found);
        Assert.Equal(expected, found.Path);
        Assert.Equal(ClaudeCodeCliSource.DesktopApp, found.Source);
    }

    // ---- What the report is told -------------------------------------------

    /// <summary>
    /// A reader comparing two scans is owed the fact that a differently-sourced CLI answered,
    /// which is only possible if the description distinguishes them.
    /// </summary>
    [Fact]
    public void Describes_each_source_distinctly()
    {
        var descriptions = Enum.GetValues<ClaudeCodeCliSource>()
            .Select(source => new ClaudeCodeCli { Path = "x", Source = source }.Description)
            .ToList();

        Assert.All(descriptions, d => Assert.False(string.IsNullOrWhiteSpace(d)));

        // The two bundled sources share wording, since the distinction between them is an
        // installation detail no reader can act on.
        Assert.Equal(descriptions.Count - 1, descriptions.Distinct().Count());
    }

    [Fact]
    public void States_the_version_of_a_bundled_install()
    {
        var cli = new ClaudeCodeCli
        {
            Path = "x",
            Source = ClaudeCodeCliSource.PackagedDesktopApp,
            Version = new Version(2, 1, 219),
        };

        Assert.Contains("2.1.219", cli.Description, StringComparison.Ordinal);
    }

    // ---- Reading the real environment --------------------------------------

    /// <summary>
    /// The environment-derived probe is what ships, so it is checked for being populated
    /// rather than for what it finds, which depends on the machine.
    /// </summary>
    [Fact]
    public void Reads_its_roots_from_the_environment()
    {
        var probe = ClaudeCodeCliProbe.FromEnvironment();

        Assert.NotEmpty(probe.ExecutableDirectories);
        Assert.False(string.IsNullOrEmpty(probe.ApplicationData));
        Assert.False(string.IsNullOrEmpty(probe.LocalApplicationData));
        Assert.False(string.IsNullOrEmpty(probe.UserProfile));
    }
}
