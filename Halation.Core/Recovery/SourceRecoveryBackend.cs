using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Halation.Core.Artifacts;
using Halation.Core.Model;

namespace Halation.Core.Recovery;

/// <summary>
/// Reads artifacts that already contain readable text: a source folder, a zipped project,
/// or a build output directory.
/// </summary>
/// <remarks>
/// The highest-coverage path in the scanner. Bundled output is read rather than skipped: a key
/// stripped from source but baked into <c>dist/</c> still ships to every user.
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
    /// <c>node_modules</c> is excluded from source scanning but not from analysis: its manifests
    /// are still collected, because dependency versions are where the findings are.
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
        "gradle.lockfile", "pipfile.lock",
    ];

    public bool CanHandle(ArtifactKind kind) =>
        kind is ArtifactKind.SourceTree
            or ArtifactKind.Archive
            or ArtifactKind.JavaArchive
            // A frozen Python application ships readable .py alongside its compiled modules,
            // and for tools with a plugin folder that source is third-party code the user
            // installed, which is exactly what is worth reading.
            or ArtifactKind.PythonBundle;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var warnings = new List<string>();
        var findings = new List<Finding>();
        var budget = new DecompilationBudget();

        var (files, considered) = artifact.IsDirectory
            ? ReadDirectory(artifact.Path, warnings, cancellationToken)
            : ReadArchive(artifact.Path, findings, budget, warnings, cancellationToken);

        // Code present but unreadable still belongs in the denominator, or coverage measures
        // how well recovery went on the files it could see rather than how much of the
        // application was actually examined.
        var unreadable = artifact.Kind == ArtifactKind.PythonBundle
            ? NotePythonLimitations(artifact, warnings)
            : 0;

        considered += unreadable;

        // Types that decompiled into scrambled text are present but not legible, and coverage
        // counts what was understood. Same rule as the .NET backends, applied here because an
        // archive can now carry an assembly through this path too.
        var readable = Math.Max(0, files.Count - budget.TypesUnreadable);

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Findings = AssemblyInspector.Collapse(findings),
            Coverage = new CoverageReport
            {
                Percent = considered == 0
                    ? 0
                    : Math.Clamp((int)Math.Round(readable / (double)considered * 100), 0, 100),
                Basis = considered == 0
                    ? "No readable text files were found."
                    : unreadable == 0
                        ? $"Read {readable:N0} of {considered:N0} candidate files."
                        : $"Read {readable:N0} source files; {unreadable:N0} further modules "
                          + "are compiled and were not readable.",
                RecoveredFileCount = files.Count,
                RecoveredBytes = files.Sum(f => (long)f.Content.Length),
                ChecksNotPossible = warnings.Distinct(StringComparer.Ordinal).Take(50).ToList(),
            },
        });
    }

    /// <summary>
    /// States what a frozen Python application keeps out of reach.
    /// </summary>
    /// <remarks>
    /// Most of a frozen application is .pyc inside an archive, which this scanner does not
    /// decompile, so the readable .py left over is often just the entry point. A short findings
    /// list here is a narrow view rather than a clean one, and the report says so.
    /// </remarks>
    /// <returns>How many modules exist but could not be read, for the coverage denominator.</returns>
    private static int NotePythonLimitations(ArtifactDescriptor artifact, List<string> warnings)
    {
        var unreadable = 0;

        try
        {
            var compiled = Directory
                .EnumerateFiles(artifact.Path, "*.pyc", SearchOption.AllDirectories)
                .Take(20_000)
                .Count();

            if (compiled > 0)
            {
                unreadable += compiled;
                warnings.Add(
                    $"{compiled:N0} compiled Python modules (.pyc) were not decompiled; only "
                    + "readable .py source was analysed.");
            }

            foreach (var archive in FindPythonArchives(artifact.Path))
            {
                // The standard library archive dominates these bundles, and counting its
                // entries is what stops a handful of loose .py files reading as the whole app.
                unreadable += CountArchiveModules(archive);

                warnings.Add(
                    $"The bundled Python archive {Path.GetFileName(archive)} was not unpacked, "
                    + "so the modules inside it were not analysed.");
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return unreadable;
    }

    private static IEnumerable<string> FindPythonArchives(string root)
    {
        foreach (var candidate in new[] { "base_library.zip", "python3.zip", "library.zip" })
        {
            var direct = Path.Combine(root, candidate);
            if (File.Exists(direct))
            {
                yield return direct;
            }

            var inner = Path.Combine(root, "_internal", candidate);
            if (File.Exists(inner))
            {
                yield return inner;
            }
        }
    }

    private static int CountArchiveModules(string archivePath)
    {
        try
        {
            using var archive = ZipFile.OpenRead(archivePath);

            return archive.Entries.Count(e =>
                e.FullName.EndsWith(".pyc", StringComparison.OrdinalIgnoreCase)
                || e.FullName.EndsWith(".py", StringComparison.OrdinalIgnoreCase));
        }
        catch (InvalidDataException)
        {
            return 0;
        }
        catch (IOException)
        {
            return 0;
        }
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
        List<Finding> findings,
        DecompilationBudget budget,
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

            var nested = ReadNestedApplications(
                archive, files, findings, budget, warnings, cancellationToken);

            // Both halves belong in the denominator: what an application inside the archive
            // contributed, and what it would have contributed had it been readable.
            considered += nested.Recovered + nested.Unread;
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
    /// Budgets for the second pass. An application is routinely larger than any source file,
    /// so the default per-entry ceiling would reject exactly the thing worth reading.
    /// </summary>
    private static readonly ArchiveLimits NestedLimits = new()
    {
        MaxFileBytes = 192L * 1024 * 1024,
        MaxTotalBytes = 512L * 1024 * 1024,
    };

    /// <summary>Cap on programs opened inside one archive, so a bundle of them cannot stall a scan.</summary>
    private const int MaxNestedApplications = 20;

    /// <summary>
    /// Recovers applications packed inside the archive, and counts the ones that could not be.
    /// </summary>
    /// <remarks>
    /// The download shape, and the one that produced the worst result this scanner has given:
    /// Halation's own release zip scored 100/100 on the strength of one theme file while the
    /// 65 MB executable beside it went unopened and unmentioned. A second pass rather than a
    /// wider first one, so ordinary source archives keep the limits they had.
    /// </remarks>
    private static (int Recovered, int Unread) ReadNestedApplications(
        ZipArchive archive,
        List<RecoveredFile> files,
        List<Finding> findings,
        DecompilationBudget budget,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var before = files.Count;
        var unread = 0;
        var opened = 0;
        var ownership = AssemblyOwnership.VendorList;

        foreach (var entry in SafeArchive.ReadEntries(
                     archive, LooksExecutable, warnings, NestedLimits, cancellationToken))
        {
            if (budget.Exhausted || opened >= MaxNestedApplications)
            {
                break;
            }

            opened++;

            switch (Recover(entry, files, findings, budget, ref ownership, warnings, cancellationToken))
            {
                case NestedOutcome.Recovered:
                    break;

                case NestedOutcome.NotTheApplication:
                    // A framework or vendor assembly shipped beside the application. Not read
                    // and not missing, so it belongs in neither half of the figure.
                    break;

                default:
                    unread++;
                    warnings.Add(
                        $"{entry.Path} is a program this scanner cannot read "
                        + $"({entry.Content.Length / (1024 * 1024)} MB). Nothing inside it was "
                        + "analysed, and the coverage figure counts it as unexamined.");
                    break;
            }
        }

        return (files.Count - before, unread);
    }

    private enum NestedOutcome { Recovered, NotTheApplication, Unreadable }

    /// <summary>
    /// Sends one packed program to whichever recovery understands it. Deliberately the same
    /// three shapes the installer backend handles, through the same helpers.
    /// </summary>
    private static NestedOutcome Recover(
        SafeArchive.Entry entry,
        List<RecoveredFile> files,
        List<Finding> findings,
        DecompilationBudget budget,
        ref AssemblyOwnership ownership,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var before = files.Count;

        if (entry.Path.EndsWith(".asar", StringComparison.OrdinalIgnoreCase))
        {
            using var asar = new MemoryStream(entry.Content, writable: false);
            ElectronRecoveryBackend.ReadAsarInto(asar, entry.Path, files, warnings, cancellationToken);

            return files.Count > before ? NestedOutcome.Recovered : NestedOutcome.Unreadable;
        }

        using var payload = new MemoryStream(entry.Content, writable: false);

        try
        {
            if (SingleFileBundle.IsBundle(payload))
            {
                payload.Position = 0;

                ownership = SingleFileRecoveryBackend.RecoverBundle(
                    SingleFileBundle.Read(payload, warnings, cancellationToken),
                    resolverBasePath: null,
                    ownership,
                    budget,
                    files,
                    findings,
                    warnings,
                    cancellationToken);

                return files.Count > before ? NestedOutcome.Recovered : NestedOutcome.Unreadable;
            }

            if (ManagedAssemblyName(payload) is not { } name)
            {
                return NestedOutcome.Unreadable;
            }

            if (!ownership.IsApplicationCode(name))
            {
                return NestedOutcome.NotTheApplication;
            }

            payload.Position = 0;

            ManagedAssemblyDecompiler.Decompile(
                name, payload, resolverBasePath: null, budget, files, findings, warnings,
                cancellationToken);

            return files.Count > before ? NestedOutcome.Recovered : NestedOutcome.Unreadable;
        }
        catch (BadImageFormatException)
        {
            return NestedOutcome.Unreadable;
        }
        catch (InvalidDataException)
        {
            return NestedOutcome.Unreadable;
        }
    }

    /// <summary>The assembly's own name, or null when the payload carries no managed metadata.</summary>
    private static string? ManagedAssemblyName(Stream payload)
    {
        try
        {
            payload.Position = 0;

            using var reader = new PEReader(payload, PEStreamOptions.LeaveOpen);

            if (!reader.HasMetadata)
            {
                return null;
            }

            var metadata = reader.GetMetadataReader();

            return metadata.IsAssembly
                ? metadata.GetString(metadata.GetAssemblyDefinition().Name) + ".dll"
                : null;
        }
        catch (BadImageFormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Names worth opening as programs. Matched by extension rather than by content because
    /// the alternative is decompressing every entry in the archive to look at its first bytes.
    /// </summary>
    private static bool LooksExecutable(string relativePath) =>
        !IsVendored(relativePath)
        && (relativePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".asar", StringComparison.OrdinalIgnoreCase));

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
