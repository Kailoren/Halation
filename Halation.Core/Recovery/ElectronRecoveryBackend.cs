using System.IO.Compression;

using Halation.Core.Artifacts;
using Halation.Core.Model;

namespace Halation.Core.Recovery;

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
                considered += ReadAsarInto(stream, label, files, warnings, cancellationToken);
            }
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Findings = SignatureFindings(artifact, warnings, cancellationToken),
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
    /// Whether the application's own launcher is signed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An Electron application is a renamed copy of the Electron binary with the real code in an
    /// asar beside it, so the launcher is a plain native executable and reads exactly like any
    /// other. This path never asked, which meant a whole ecosystem of downloads was analysed in
    /// full and never told the reader whether anybody had put their name to the file.
    /// </para>
    /// <para>
    /// <b>The same question is asked of a zipped build.</b> It was asked only of a folder, so the
    /// identical application scored 99 unpacked and 100 zipped: the launcher was sitting in the
    /// archive and nothing looked at it. Two scans of one build disagreeing is worse than either
    /// answer, because whichever one the reader took, the tool was wrong about the other.
    /// </para>
    /// <para>
    /// Not for a bare <c>.asar</c>, which is the code without the program around it, so there is
    /// no launcher to ask about.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<Finding> SignatureFindings(
        ArtifactDescriptor artifact,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        if (artifact.IsDirectory)
        {
            try
            {
                return Directory
                    .EnumerateFiles(artifact.Path, "*.exe", SearchOption.TopDirectoryOnly)
                    .Take(MaxLaunchers)
                    .Select(exe => ExecutableSignature.Check(
                        exe, Path.GetRelativePath(artifact.Path, exe).Replace('\\', '/')))
                    .OfType<Finding>()
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

        return artifact.Kind == ArtifactKind.ElectronApp
            ? ZippedLauncherFindings(artifact, warnings, cancellationToken)
            : [];
    }

    /// <summary>How many executables beside the asar are worth asking about.</summary>
    private static int MaxLaunchers => 10;

    /// <summary>
    /// Ceiling on a launcher lifted out of an archive to be inspected.
    /// </summary>
    /// <remarks>
    /// Larger than <see cref="ArchiveLimits.MaxFileBytes"/>, which is a source file's budget and
    /// would reject every Electron launcher there is: the one measured here is 246 MB, because a
    /// launcher is the whole Chromium runtime with the application's icon on it. Every other
    /// bound the archive reader applies still applies, the compression ratio included, and this
    /// is one entry per archive rather than a budget for all of them.
    /// </remarks>
    private const long MaxLauncherBytes = 512L * 1024 * 1024;

    /// <summary>
    /// Checks the launcher inside a zipped Electron build, one entry at a time.
    /// </summary>
    /// <remarks>
    /// The entry goes to a temporary file because both halves of the answer need one: a PE
    /// header read wants a seekable stream, and the catalogue lookup underneath
    /// <see cref="ExecutableSignature"/> hashes a file by handle. It is deleted immediately
    /// afterwards, and nothing else in this backend writes to disk.
    /// </remarks>
    private static IReadOnlyList<Finding> ZippedLauncherFindings(
        ArtifactDescriptor artifact,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        ZipArchive archive;

        try
        {
            archive = ZipFile.OpenRead(artifact.Path);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException
                                      or UnauthorizedAccessException)
        {
            return [];
        }

        using (archive)
        {
            var findings = new List<Finding>();

            foreach (var entry in LauncherEntries(archive))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (entry.Length > MaxLauncherBytes
                    || (entry.CompressedLength > 0
                        && entry.Length / entry.CompressedLength
                           > ArchiveLimits.Default.MaxCompressionRatio))
                {
                    // Reported rather than skipped quietly, because the finding this would have
                    // produced is about a file the reader can see in their own archive.
                    warnings.Add(
                        $"{entry.FullName} was not checked for a signature: it is larger than "
                        + $"{MaxLauncherBytes / (1024 * 1024)} MB or compressed beyond what this "
                        + "scanner will expand.");

                    continue;
                }

                var temporary = Path.Combine(
                    Path.GetTempPath(), "halation-launcher-" + Guid.NewGuid().ToString("N") + ".exe");

                try
                {
                    if (!ExtractTo(entry, temporary, cancellationToken))
                    {
                        warnings.Add(
                            $"{entry.FullName} was not checked for a signature: it expanded "
                            + "beyond its declared size.");

                        continue;
                    }

                    if (ExecutableSignature.Check(temporary, entry.FullName.Replace('\\', '/'))
                        is { } finding)
                    {
                        findings.Add(finding);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                              or InvalidDataException)
                {
                    warnings.Add($"{entry.FullName} could not be read to check its signature.");
                }
                finally
                {
                    Delete(temporary);
                }
            }

            return findings;
        }
    }

    /// <summary>
    /// The executables sitting beside the application's own resources folder.
    /// </summary>
    /// <remarks>
    /// Anchored on the asar rather than on "any .exe in the zip", which would also pick up
    /// whatever ships inside the application's own resources. The launcher is the file in the
    /// same directory as <c>resources/</c>, which is exactly what the folder scan looks at.
    /// </remarks>
    private static IEnumerable<ZipArchiveEntry> LauncherEntries(ZipArchive archive)
    {
        var roots = archive.Entries
            .Select(e => e.FullName.Replace('\\', '/'))
            .Where(name => name.EndsWith(".asar", StringComparison.OrdinalIgnoreCase)
                           && name.Contains("resources/", StringComparison.OrdinalIgnoreCase))
            .Select(name => name[..name.IndexOf("resources/", StringComparison.OrdinalIgnoreCase)])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (roots.Count == 0)
        {
            yield break;
        }

        var found = 0;

        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');

            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (roots.Any(root => name.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                                  && !name[root.Length..].Contains('/')))
            {
                yield return entry;

                if (++found == MaxLaunchers)
                {
                    yield break;
                }
            }
        }
    }

    /// <summary>
    /// Writes one entry to a file, stopping if it produces more than it declared.
    /// </summary>
    /// <remarks>
    /// The budget is enforced while decompressing rather than taken from the central directory,
    /// which is where <see cref="SafeArchive"/> enforces it and for the same reason: the
    /// declared length is a number the archive's author chose.
    /// </remarks>
    private static bool ExtractTo(
        ZipArchiveEntry entry, string path, CancellationToken cancellationToken)
    {
        using var source = entry.Open();
        using var destination = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None);

        var buffer = new byte[81920];
        long written = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var read = source.Read(buffer, 0, buffer.Length);

            if (read == 0)
            {
                return true;
            }

            written += read;

            if (written > MaxLauncherBytes)
            {
                return false;
            }

            destination.Write(buffer, 0, read);
        }
    }

    private static void Delete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing worth failing a scan over. The file is in the temporary directory and
            // carries no content of the reader's; it was copied out of the archive they dropped.
        }
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
    /// Reads one asar into <paramref name="files"/>, returning how many entries were worth
    /// reading, which is the denominator of the coverage figure.
    /// </summary>
    /// <remarks>
    /// Shared with <see cref="InstallerRecoveryBackend"/>: an asar lifted out of an installer
    /// is the same artifact as one found in an installed folder, and letting the two paths
    /// drift would mean the same application scored differently depending on which form of it
    /// was dropped in.
    /// </remarks>
    internal static int ReadAsarInto(
        Stream stream,
        string label,
        ICollection<RecoveredFile> files,
        IList<string> warnings,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<AsarReader.AsarEntry> entries;

        try
        {
            entries = AsarReader.Read(stream, warnings, cancellationToken: cancellationToken);
        }
        catch (EndOfStreamException)
        {
            warnings.Add($"{label} is truncated.");
            return 0;
        }
        catch (IOException)
        {
            warnings.Add($"{label} could not be read.");
            return 0;
        }

        var considered = 0;

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

        return considered;
    }

    /// <summary>
    /// Bundled Electron apps ship their dependencies inside the asar, so vendored paths are
    /// filtered here rather than analysed as application code.
    /// </summary>
    internal static bool IsInteresting(string path)
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
