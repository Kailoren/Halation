using VibeCheck.Core.Model;

namespace VibeCheck.Core.Artifacts;

/// <summary>
/// Checks on what a distribution ships, rather than on what its code does.
/// </summary>
/// <remarks>
/// These are mistakes of packaging, not of programming: the code may be perfectly correct
/// and still ship a file that should not have left the developer's machine. They are invisible
/// to source analysis because the problem is the file's presence, so they run against the
/// artifact listing instead.
/// </remarks>
public static class PackagingChecks
{
    public static IReadOnlyList<Finding> Run(ArtifactDescriptor artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        if (!artifact.IsDirectory)
        {
            return [];
        }

        var findings = new List<Finding>();
        var files = Enumerate(artifact.Path);

        AddIfPresent(
            findings,
            files,
            name => name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase),
            new Finding
            {
                RuleId = "VC-PKG-001",
                Title = "Debug symbols shipped with the release",
                Severity = Severity.Low,
                Category = FindingCategory.BinaryHygiene,
                Description =
                    "The distribution contains .pdb debug symbol files. These carry original "
                    + "source file paths, local variable names, and line numbers, which makes the "
                    + "application markedly easier to reverse engineer and can leak the directory "
                    + "layout of the machine that built it.",
                Remediation =
                    "Exclude symbols from release output, for example by setting DebugType to none "
                    + "for the Release configuration, or by removing the .pdb files during packaging. "
                    + "Keep them privately for crash analysis.",
            });

        AddIfPresent(
            findings,
            files,
            name => Path.GetFileName(name).StartsWith(".env", StringComparison.OrdinalIgnoreCase)
                    && !name.EndsWith(".example", StringComparison.OrdinalIgnoreCase)
                    && !name.EndsWith(".sample", StringComparison.OrdinalIgnoreCase),
            new Finding
            {
                RuleId = "VC-PKG-002",
                Title = "Environment file shipped with the application",
                Severity = Severity.High,
                Category = FindingCategory.Secrets,
                Description =
                    "The distribution includes a .env file. These normally hold the credentials the "
                    + "application uses, and shipping one hands every value in it to everyone who "
                    + "downloads the application.",
                Remediation =
                    "Remove it from the packaged output and rotate anything it contained. Ship a "
                    + ".env.example with the keys but no values instead.",
            });

        AddIfPresent(
            findings,
            files,
            name => name.EndsWith(".js.map", StringComparison.OrdinalIgnoreCase),
            new Finding
            {
                RuleId = "VC-PKG-003",
                Title = "Source maps shipped with the release",
                Severity = Severity.Low,
                Category = FindingCategory.BinaryHygiene,
                Description =
                    "The distribution contains JavaScript source maps, which reconstruct the "
                    + "original unminified source including comments and file structure.",
                Remediation =
                    "Disable source map generation for production builds, or upload them to your "
                    + "error reporting service rather than shipping them to users.",
            });

        AddIfPresent(
            findings,
            files,
            name => name.Replace('\\', '/').Contains("/.git/", StringComparison.Ordinal),
            new Finding
            {
                RuleId = "VC-PKG-004",
                Title = "Version control directory shipped with the application",
                Severity = Severity.High,
                Category = FindingCategory.Secrets,
                Description =
                    "The distribution contains a .git directory. It holds the project's full "
                    + "history, so any credential ever committed and later removed is still "
                    + "recoverable from it, along with branch names and commit messages.",
                Remediation =
                    "Exclude .git from packaging and rotate any credential that appears anywhere in "
                    + "the repository history, not just in the current files.",
            });

        return findings;
    }

    private static void AddIfPresent(
        List<Finding> findings,
        IReadOnlyList<string> files,
        Func<string, bool> predicate,
        Finding template)
    {
        var matches = files.Where(predicate).ToList();
        if (matches.Count == 0)
        {
            return;
        }

        findings.Add(template with
        {
            FilePath = matches[0],
            Description = matches.Count == 1
                ? template.Description
                : $"{template.Description} {matches.Count} such files are present.",
        });
    }

    /// <summary>
    /// True for local build output that no distribution contains.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These checks describe what an application ships, so they only mean anything about files
    /// that would actually reach a user. Dropping in a source folder, which is the whole
    /// before-you-ship case, otherwise reported <c>bin/Debug/App.pdb</c> as "debug symbols
    /// shipped with the release" - a Debug artifact, in a directory that is not the release,
    /// in a tree that is not a distribution.
    /// </para>
    /// <para>
    /// <c>bin/Release</c> is deliberately still counted: that one is the release, and a .pdb
    /// sitting in it is exactly the mistake this check exists to catch. Nor is <c>.git</c>
    /// excluded here, because VC-PKG-004 is looking for it.
    /// </para>
    /// </remarks>
    private static bool IsBuildScratch(string relativePath)
    {
        var segments = relativePath.Split('/');

        for (var i = 0; i < segments.Length; i++)
        {
            if (segments[i].Equals("obj", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (segments[i].Equals("bin", StringComparison.OrdinalIgnoreCase)
                && i + 1 < segments.Length
                && segments[i + 1].Equals("Debug", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<string> Enumerate(string root)
    {
        try
        {
            return Directory
                .EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
                .Where(f => !IsBuildScratch(f))
                .Take(50_000)
                .ToList();
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }
}
