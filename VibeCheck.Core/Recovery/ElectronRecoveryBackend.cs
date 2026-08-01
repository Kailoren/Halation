using System.IO.Compression;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Recovers JavaScript from Electron applications by reading their asar container.
/// </summary>
/// <remarks>
/// Electron is the most valuable target for the downloaded-binary case. The shipped asar
/// holds the application's real JavaScript, frequently unminified, so a distributed desktop
/// app can be analysed at close to source fidelity without the developer's repository.
/// </remarks>
public sealed class ElectronRecoveryBackend : IRecoveryBackend
{
    public bool CanHandle(ArtifactKind kind) =>
        kind is ArtifactKind.ElectronApp or ArtifactKind.AsarArchive;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var warnings = new List<string>();
        var files = new List<RecoveredFile>();
        var considered = 0;

        foreach (var (label, stream) in OpenAsars(artifact, warnings))
        {
            using (stream)
            {
                IReadOnlyList<AsarReader.AsarEntry> entries;
                try
                {
                    entries = AsarReader.Read(stream, warnings, cancellationToken: cancellationToken);
                }
                catch (EndOfStreamException)
                {
                    warnings.Add($"{label} is truncated.");
                    continue;
                }
                catch (IOException)
                {
                    warnings.Add($"{label} could not be read.");
                    continue;
                }

                foreach (var entry in entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!IsInteresting(entry.Path))
                    {
                        continue;
                    }

                    considered++;

                    if (AsarReader.AsText(entry) is not { } text)
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
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Coverage = new CoverageReport
            {
                Percent = considered == 0
                    ? 0
                    : Math.Clamp((int)Math.Round(files.Count / (double)considered * 100), 0, 100),
                Basis = considered == 0
                    ? "No readable application code was found in the archive."
                    : $"Read {files.Count:N0} of {considered:N0} application files from the asar archive.",
                RecoveredFileCount = files.Count,
                RecoveredBytes = files.Sum(f => (long)f.Content.Length),
                ChecksNotPossible = BuildLimitations(warnings),
            },
        });
    }

    /// <summary>
    /// Yields every asar to read. An installed app keeps one at resources/app.asar; a
    /// distributed zip has the same layout inside; a bare .asar is read directly.
    /// </summary>
    private static IEnumerable<(string Label, Stream Stream)> OpenAsars(
        ArtifactDescriptor artifact,
        List<string> warnings)
    {
        if (artifact.Kind == ArtifactKind.AsarArchive && !artifact.IsDirectory)
        {
            yield return (artifact.Name, File.OpenRead(artifact.Path));
            yield break;
        }

        if (artifact.IsDirectory)
        {
            foreach (var path in FindAsarFiles(artifact.Path))
            {
                yield return (
                    Path.GetRelativePath(artifact.Path, path).Replace('\\', '/'),
                    File.OpenRead(path));
            }

            yield break;
        }

        // A zipped Electron app: lift the asar into memory rather than to disk, keeping
        // the no-extraction guarantee intact.
        ZipArchive archive;
        try
        {
            archive = ZipFile.OpenRead(artifact.Path);
        }
        catch (InvalidDataException)
        {
            warnings.Add("Archive is corrupt and could not be read.");
            yield break;
        }
        catch (IOException)
        {
            warnings.Add("Archive could not be opened.");
            yield break;
        }

        using (archive)
        {
            var entries = SafeArchive.ReadEntries(
                archive,
                name => name.EndsWith(".asar", StringComparison.OrdinalIgnoreCase),
                warnings);

            foreach (var entry in entries)
            {
                yield return (entry.Path, new MemoryStream(entry.Content, writable: false));
            }
        }
    }

    private static IEnumerable<string> FindAsarFiles(string root)
    {
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((root, 0));

        while (pending.Count > 0)
        {
            var (directory, depth) = pending.Dequeue();

            string[] files;
            try
            {
                files = Directory.GetFiles(directory, "*.asar");
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                yield return file;
            }

            // Bounded: Electron always places resources/ within a level or two of the root,
            // and an unbounded walk over an untrusted tree is a hazard in itself.
            if (depth >= 4)
            {
                continue;
            }

            string[] subdirectories;
            try
            {
                subdirectories = Directory.GetDirectories(directory);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var subdirectory in subdirectories)
            {
                if (new DirectoryInfo(subdirectory).LinkTarget is null)
                {
                    pending.Enqueue((subdirectory, depth + 1));
                }
            }
        }
    }

    /// <summary>
    /// Bundled Electron apps ship their dependencies inside the asar, so vendored paths are
    /// filtered here rather than analysed as application code.
    /// </summary>
    private static bool IsInteresting(string path)
    {
        var name = Path.GetFileName(path);

        if (path.Split('/').Contains("node_modules"))
        {
            return name.Equals("package.json", StringComparison.OrdinalIgnoreCase);
        }

        if (name.Equals("package.json", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith(".env", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return RecoveredFile.LanguageOf(path) != SourceLanguage.Unknown;
    }

    private static List<string> BuildLimitations(List<string> warnings)
    {
        var limitations = warnings.Distinct(StringComparer.Ordinal).Take(50).ToList();

        // Native addons are real executable code that this scanner cannot read, so their
        // presence is stated rather than left to look like an absence of findings.
        if (warnings.Any(w => w.Contains("unpacked", StringComparison.OrdinalIgnoreCase)))
        {
            limitations.Add(
                "Native modules stored outside the archive were not analysed; they contain "
                + "compiled code this scanner cannot read.");
        }

        return limitations;
    }
}
