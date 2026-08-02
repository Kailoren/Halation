namespace VibeCheck.Core.DeepPass;

/// <summary>
/// Which install a Claude Code executable came from.
/// </summary>
/// <remarks>
/// Recorded rather than discarded because the five kinds are not equally durable. A standalone
/// install sits at a stable path its own installer maintains. The copy bundled with the desktop
/// app lives inside that app's private storage under a version-numbered directory, so it moves
/// on every update and is not ours to depend on. A report that says which one answered lets a
/// reader make sense of a scan that worked last week and does not today.
/// </remarks>
public enum ClaudeCodeCliSource
{
    /// <summary>Found on PATH, which is where a properly installed CLI puts itself.</summary>
    Path,

    /// <summary>A global npm install, in npm's own bin directory.</summary>
    NpmGlobal,

    /// <summary>The native installer's location under the user's home directory.</summary>
    NativeInstaller,

    /// <summary>
    /// Bundled inside the packaged (MSIX/Store) desktop app's private storage.
    /// </summary>
    PackagedDesktopApp,

    /// <summary>Bundled with an unpackaged desktop app install.</summary>
    DesktopApp,
}

/// <summary>A Claude Code executable that was actually found on disk.</summary>
public sealed record ClaudeCodeCli
{
    public required string Path { get; init; }

    public required ClaudeCodeCliSource Source { get; init; }

    /// <summary>
    /// The version, when the install encodes one in its path. Null for installs that do not,
    /// which is most of them: the executable itself is not run to ask.
    /// </summary>
    public Version? Version { get; init; }

    /// <summary>How this install is described in a report, for the reader deciding whether to trust it.</summary>
    public string Description => Source switch
    {
        ClaudeCodeCliSource.Path => "a Claude Code CLI on PATH",
        ClaudeCodeCliSource.NpmGlobal => "an npm-installed Claude Code CLI",
        ClaudeCodeCliSource.NativeInstaller => "a Claude Code CLI from the native installer",
        ClaudeCodeCliSource.PackagedDesktopApp or ClaudeCodeCliSource.DesktopApp =>
            $"the Claude Code CLI bundled with the Claude desktop app{VersionSuffix}",
        _ => "a Claude Code CLI",
    };

    private string VersionSuffix => Version is null ? string.Empty : $" ({Version})";
}

/// <summary>
/// The directories a search looks in. Supplied rather than read at the point of use so the
/// search can be tested against a laid-out temporary directory instead of the machine it runs on.
/// </summary>
public sealed record ClaudeCodeCliProbe
{
    /// <summary>Directories to treat as PATH.</summary>
    public IReadOnlyList<string> ExecutableDirectories { get; init; } = [];

    /// <summary>Roaming application data, i.e. <c>%APPDATA%</c>.</summary>
    public string? ApplicationData { get; init; }

    /// <summary>Local application data, i.e. <c>%LOCALAPPDATA%</c>.</summary>
    public string? LocalApplicationData { get; init; }

    /// <summary>The user's home directory.</summary>
    public string? UserProfile { get; init; }

    public static ClaudeCodeCliProbe FromEnvironment() => new()
    {
        ExecutableDirectories = SplitPath(Environment.GetEnvironmentVariable("PATH")),
        ApplicationData = Folder(Environment.SpecialFolder.ApplicationData),
        LocalApplicationData = Folder(Environment.SpecialFolder.LocalApplicationData),
        UserProfile = Folder(Environment.SpecialFolder.UserProfile),
    };

    private static string? Folder(Environment.SpecialFolder folder)
    {
        var path = Environment.GetFolderPath(folder);
        return string.IsNullOrEmpty(path) ? null : path;
    }

    private static IReadOnlyList<string> SplitPath(string? value) =>
        string.IsNullOrEmpty(value)
            ? []
            : value.Split(
                System.IO.Path.PathSeparator,
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// Finds a Claude Code executable to run the deep pass through.
/// </summary>
/// <remarks>
/// <para>
/// The desktop app bundles a working CLI, and looking for it is not as simple as reading
/// <c>%APPDATA%</c>. When the desktop app was installed as a package (MSIX, i.e. from the
/// Store), Windows redirects its view of roaming application data into the package's private
/// storage. A process running inside that package sees the executable at
/// <c>%APPDATA%\Claude\claude-code\&lt;version&gt;\claude.exe</c>; VibeCheck, which is not in
/// the package, looks at that same path and finds nothing there at all. The real file is under
/// <c>%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\</c>, and only the unredirected path
/// works from out here. This was confirmed on a machine where the two views disagreed: the
/// same absolute path executed successfully from inside the package and produced
/// "is not recognized" from a normal shell.
/// </para>
/// <para>
/// Order runs from most durable to least. A standalone install is preferred over the bundled
/// copy even when both exist, because the bundled one sits in another application's private
/// storage under a version-numbered directory that moves whenever that application updates.
/// It is searched last rather than not at all, because for most people the desktop app is the
/// only Claude Code they have, and refusing to look there would mean the deep pass is
/// unavailable to them for no reason they could act on.
/// </para>
/// </remarks>
public static class ClaudeCodeCliLocator
{
    /// <summary>Names the executable goes by, in the order they should be preferred.</summary>
    private static readonly string[] ExecutableNames = ["claude.exe", "claude.cmd", "claude"];

    /// <summary>The desktop app's package family, whose publisher suffix varies by channel.</summary>
    private const string PackagePattern = "Claude_*";

    /// <summary>
    /// Searches for a usable executable and returns the first one found, or null when the
    /// machine has none. Never throws: an unreadable directory is a location that did not
    /// match, not a failed scan.
    /// </summary>
    public static ClaudeCodeCli? Locate(ClaudeCodeCliProbe? probe = null)
    {
        probe ??= ClaudeCodeCliProbe.FromEnvironment();

        return FindOnPath(probe)
               ?? FindNpmGlobal(probe)
               ?? FindNativeInstaller(probe)
               ?? FindPackagedDesktopApp(probe)
               ?? FindDesktopApp(probe);
    }

    /// <summary>1. A standalone install that put itself on PATH.</summary>
    private static ClaudeCodeCli? FindOnPath(ClaudeCodeCliProbe probe)
    {
        foreach (var directory in probe.ExecutableDirectories)
        {
            foreach (var name in ExecutableNames)
            {
                if (Exists(Combine(directory, name)) is { } path)
                {
                    return new ClaudeCodeCli { Path = path, Source = ClaudeCodeCliSource.Path };
                }
            }
        }

        return null;
    }

    /// <summary>2. A global npm install, whose bin directory is not always on PATH.</summary>
    private static ClaudeCodeCli? FindNpmGlobal(ClaudeCodeCliProbe probe)
    {
        if (probe.ApplicationData is not { } appData)
        {
            return null;
        }

        foreach (var name in ExecutableNames)
        {
            if (Exists(Combine(appData, "npm", name)) is { } path)
            {
                return new ClaudeCodeCli { Path = path, Source = ClaudeCodeCliSource.NpmGlobal };
            }
        }

        return null;
    }

    /// <summary>3. The native installer's home-directory location.</summary>
    private static ClaudeCodeCli? FindNativeInstaller(ClaudeCodeCliProbe probe)
    {
        if (probe.UserProfile is not { } home)
        {
            return null;
        }

        foreach (var name in ExecutableNames)
        {
            if (Exists(Combine(home, ".local", "bin", name)) is { } path)
            {
                return new ClaudeCodeCli
                {
                    Path = path,
                    Source = ClaudeCodeCliSource.NativeInstaller,
                };
            }
        }

        return null;
    }

    /// <summary>
    /// 4. Bundled inside the packaged desktop app. The publisher suffix on the package
    /// directory is not hardcoded, so a differently-signed channel still resolves.
    /// </summary>
    private static ClaudeCodeCli? FindPackagedDesktopApp(ClaudeCodeCliProbe probe)
    {
        if (probe.LocalApplicationData is not { } localAppData)
        {
            return null;
        }

        var packages = Combine(localAppData, "Packages");

        foreach (var package in Directories(packages, PackagePattern))
        {
            var root = Combine(package, "LocalCache", "Roaming", "Claude", "claude-code");

            if (HighestVersioned(root, ClaudeCodeCliSource.PackagedDesktopApp) is { } found)
            {
                return found;
            }
        }

        return null;
    }

    /// <summary>5. Bundled with an unpackaged desktop app install, where no redirection applies.</summary>
    private static ClaudeCodeCli? FindDesktopApp(ClaudeCodeCliProbe probe) =>
        probe.ApplicationData is { } appData
            ? HighestVersioned(
                Combine(appData, "Claude", "claude-code"),
                ClaudeCodeCliSource.DesktopApp)
            : null;

    /// <summary>
    /// Picks the newest install under a directory of version-named subdirectories.
    /// </summary>
    /// <remarks>
    /// Versions are compared as versions and not as text, because the obvious string sort gets
    /// it backwards exactly when it matters: "2.1.99" sorts above "2.1.219" and would pin a
    /// machine to an install two hundred releases stale. Directories whose names do not parse
    /// are still considered, after every one that does, so an unrecognised naming scheme costs
    /// precedence rather than the whole location.
    /// </remarks>
    private static ClaudeCodeCli? HighestVersioned(string root, ClaudeCodeCliSource source)
    {
        var candidates = Directories(root, "*")
            .Select(directory => (
                Directory: directory,
                Version: Version.TryParse(System.IO.Path.GetFileName(directory), out var version)
                    ? version
                    : null))
            .OrderByDescending(candidate => candidate.Version is not null)
            .ThenByDescending(candidate => candidate.Version)
            .ThenByDescending(candidate => candidate.Directory, StringComparer.OrdinalIgnoreCase);

        foreach (var (directory, version) in candidates)
        {
            foreach (var name in ExecutableNames)
            {
                if (Exists(Combine(directory, name)) is { } path)
                {
                    return new ClaudeCodeCli { Path = path, Source = source, Version = version };
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Subdirectories matching a pattern, or none when the directory is missing or unreadable.
    /// A location we cannot look in is a location that did not match.
    /// </summary>
    private static IEnumerable<string> Directories(string root, string pattern)
    {
        try
        {
            return System.IO.Directory.Exists(root)
                ? System.IO.Directory.EnumerateDirectories(root, pattern).ToList()
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string Combine(params string[] parts) => System.IO.Path.Combine(parts);

    /// <summary>The path if it is a file we can see, otherwise null.</summary>
    private static string? Exists(string path)
    {
        try
        {
            return System.IO.File.Exists(path) ? path : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
