using System.IO.Compression;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Reads artifacts that already contain readable text: a source folder, a zipped project,
/// or a build output directory.
/// </summary>
/// <remarks>
/// This is the highest-coverage path in the scanner and the one the pre-release persona
/// hits, since they still have their project. Bundled output is read too, not skipped:
/// a committed key that was stripped from source but baked into <c>dist/</c> is still
/// shipped to every user, and the bundle is what actually gets distributed.
/// </remarks>
public sealed class SourceRecoveryBackend : IRecoveryBackend
{
    private const int MaxFiles = 20_000;
    private const long MaxFileBytes = 8L * 1024 * 1024;
    private const long MaxTotalBytes = 256L * 1024 * 1024;

    /// <summary>
    /// Directories that are never worth walking for source.
    /// </summary>
    /// <remarks>
    /// <c>node_modules</c> is excluded from source scanning but not from analysis: its
    /// manifests are still collected below, because dependency versions are exactly where
    /// the interesting findings live. Scanning every vendored file would multiply the work
    /// by a hundred for findings the user cannot act on anyway.
    /// </remarks>
    private static readonly string[] SkippedDirectories =
    [
        ".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__",
        ".gradle", ".idea", ".vs", "obj",
    ];

    private static readonly string[] ManifestNames =
    [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pyproject.toml", "poetry.lock", "gemfile.lock",
        "pom.xml", "build.gradle", "composer.lock", "cargo.lock", "go.sum",
    ];

    public bool CanHandle(ArtifactKind kind) =>
        kind is ArtifactKind.SourceTree or ArtifactKind.Archive or ArtifactKind.JavaArchive;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var warnings = new List<string>();

        var (files, considered) = artifact.IsDirectory
            ? ReadDirectory(artifact.Path, warnings, cancellationToken)
            : ReadArchive(artifact.Path, warnings, cancellationToken);

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Coverage = new CoverageReport
            {
                Percent = considered == 0
                    ? 0
                    : Math.Clamp((int)Math.Round(files.Count / (double)considered * 100), 0, 100),
                Basis = considered == 0
                    ? "No readable text files were found."
                    : $"Read {files.Count:N0} of {considered:N0} candidate text files.",
                RecoveredFileCount = files.Count,
                RecoveredBytes = files.Sum(f => (long)f.Content.Length),
                ChecksNotPossible = warnings.Distinct(StringComparer.Ordinal).Take(50).ToList(),
            },
        });
    }

    private static (List<RecoveredFile> Files, int Considered) ReadDirectory(
        string root,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var files = new List<RecoveredFile>();
        var considered = 0;
        long total = 0;

        foreach (var path in EnumerateFiles(root, warnings))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (files.Count >= MaxFiles || total >= MaxTotalBytes)
            {
                warnings.Add("Stopped reading at the scanner's file or size limit.");
                break;
            }

            var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
            if (!ShouldRead(relative))
            {
                continue;
            }

            considered++;

            FileInfo info;
            try
            {
                info = new FileInfo(path);
            }
            catch (IOException)
            {
                continue;
            }

            if (info.Length > MaxFileBytes)
            {
                warnings.Add($"Skipped {relative}: larger than the per-file limit.");
                continue;
            }

            byte[] bytes;
            try
            {
                bytes = File.ReadAllBytes(path);
            }
            catch (IOException)
            {
                warnings.Add($"Skipped {relative}: unreadable.");
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                warnings.Add($"Skipped {relative}: access denied.");
                continue;
            }

            if (SafeArchive.DecodeText(bytes) is not { } text)
            {
                continue;
            }

            total += bytes.Length;
            files.Add(new RecoveredFile
            {
                RelativePath = relative,
                Content = text,
                Language = RecoveredFile.LanguageOf(relative),
            });
        }

        return (files, considered);
    }

    private static (List<RecoveredFile> Files, int Considered) ReadArchive(
        string path,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var files = new List<RecoveredFile>();
        var considered = 0;

        try
        {
            using var archive = ZipFile.OpenRead(path);

            foreach (var entry in SafeArchive.ReadEntries(
                         archive,
                         name => { if (ShouldRead(name)) { considered++; return true; } return false; },
                         warnings,
                         cancellationToken: cancellationToken))
            {
                if (SafeArchive.DecodeText(entry.Content) is not { } text)
                {
                    continue;
                }

                files.Add(new RecoveredFile
                {
                    RelativePath = entry.Path,
                    Content = text,
                    Language = RecoveredFile.LanguageOf(entry.Path),
                });
            }
        }
        catch (InvalidDataException)
        {
            warnings.Add("Archive is corrupt and could not be read.");
        }
        catch (IOException)
        {
            warnings.Add("Archive could not be opened.");
        }

        return (files, considered);
    }

    /// <summary>
    /// Decides whether a path is worth reading. Vendored trees are skipped except for their
    /// manifests, which drive the dependency checks.
    /// </summary>
    private static bool ShouldRead(string relativePath)
    {
        var name = Path.GetFileName(relativePath);

        if (IsVendored(relativePath))
        {
            return ManifestNames.Contains(name, StringComparer.OrdinalIgnoreCase);
        }

        if (ManifestNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        // Environment files are the richest single source of leaked credentials and carry
        // no extension worth matching, so they are admitted by name.
        if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return RecoveredFile.LanguageOf(relativePath) != SourceLanguage.Unknown;
    }

    private static bool IsVendored(string relativePath) =>
        relativePath.Split('/').Any(segment =>
            SkippedDirectories.Contains(segment, StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Walks the tree without following directory symlinks, so a crafted junction cannot
    /// send the scan outside the dropped folder or into a cycle.
    /// </summary>
    private static IEnumerable<string> EnumerateFiles(string root, List<string> warnings)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var directory = pending.Pop();

            string[] entries;
            try
            {
                entries = Directory.GetFiles(directory);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (IOException)
            {
                continue;
            }

            foreach (var file in entries)
            {
                yield return file;
            }

            string[] subdirectories;
            try
            {
                subdirectories = Directory.GetDirectories(directory);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (IOException)
            {
                continue;
            }

            foreach (var subdirectory in subdirectories)
            {
                var info = new DirectoryInfo(subdirectory);

                if (info.LinkTarget is not null)
                {
                    warnings.Add(
                        $"Did not follow the link at {Path.GetRelativePath(root, subdirectory).Replace('\\', '/')}.");
                    continue;
                }

                pending.Push(subdirectory);
            }
        }
    }
}
