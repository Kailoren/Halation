using SharpCompress.Archives;
using SharpCompress.Readers;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Recovers the application packed inside a Windows installer.
/// </summary>
/// <remarks>
/// <para>
/// This is the download-and-check case as it actually arrives. Almost nothing is distributed
/// as a bare executable; it comes as an installer, and until this existed every one of them
/// reported zero coverage while the application sat readable a few layers in.
/// </para>
/// <para>
/// The chain for an Electron build is installer, then a nested archive, then the asar, and
/// only the last of those holds anything a rule can read. Each layer is opened in memory and
/// bounded independently. Nothing is written to disk and nothing is executed, which matters
/// more here than anywhere else in the scanner: an installer is a program whose whole purpose
/// is to modify the machine, and the entire point is to read it without running it.
/// </para>
/// </remarks>
public sealed class InstallerRecoveryBackend : IRecoveryBackend
{
    /// <summary>
    /// Budgets for the nested path, which are necessarily larger than
    /// <see cref="ArchiveLimits.Default"/>. The intermediate container routinely runs past
    /// 100 MB while the asar inside it is a fraction of that, so the default per-file ceiling
    /// would reject the wrapper and recover nothing.
    /// </summary>
    private static readonly ArchiveLimits Limits = new()
    {
        MaxFileBytes = 192L * 1024 * 1024,
        MaxTotalBytes = 512L * 1024 * 1024,
    };

    public bool CanHandle(ArtifactKind kind) => kind is ArtifactKind.WindowsInstaller;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var warnings = new List<string>();
        var files = new List<RecoveredFile>();
        var considered = 0;
        var payloads = 0;

        var blobs = NsisArchive.ReadBlobs(artifact.Path, warnings, cancellationToken);

        if (blobs.Count > 0)
        {
            using var installer = File.OpenRead(artifact.Path);

            foreach (var blob in blobs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var format = Identify(installer, blob);

                if (format is null)
                {
                    continue;
                }

                var found = Read(installer, blob, format, files, warnings, cancellationToken);

                // Counts payloads that actually held source, not every blob we looked at.
                // Most of them are installer plugins and the uninstaller, and saying an
                // application was read "across 8 payloads" when seven were DLLs overstates
                // what the scan touched.
                if (found > 0)
                {
                    payloads++;
                }

                considered += found;
            }
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Coverage = BuildCoverage(files, considered, payloads, blobs.Count, warnings),
        });
    }

    /// <summary>
    /// Identifies a payload by its leading bytes. NSIS keeps file names in bytecode rather
    /// than a table, so content is the only thing available to go on.
    /// </summary>
    private static string? Identify(Stream installer, NsisArchive.Blob blob)
    {
        var head = new byte[8];

        try
        {
            using var stream = NsisArchive.Open(installer, blob, leaveOpen: true);
            var read = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);

            return read < head.Length ? null : NsisArchive.SniffFormat(head);
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static int Read(
        Stream installer,
        NsisArchive.Blob blob,
        string format,
        List<RecoveredFile> files,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        switch (format)
        {
            case "asar":
                using (var stream = NsisArchive.Open(installer, blob, leaveOpen: true))
                {
                    return ElectronRecoveryBackend.ReadAsarInto(
                        stream, "the installer's asar archive", files, warnings, cancellationToken);
                }

            case "7z" or "zip":
                return ReadNestedArchive(installer, blob, files, warnings, cancellationToken);

            default:
                // A packed native binary or an installer plugin. Neither is readable, and
                // neither is worth a warning: saying so for every DLL would bury the real
                // limitations under noise.
                return 0;
        }
    }

    /// <summary>
    /// Reads the archive an installer wraps its payload in, looking for an asar.
    /// </summary>
    private static int ReadNestedArchive(
        Stream installer,
        NsisArchive.Blob blob,
        List<RecoveredFile> files,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        IArchive archive;

        // Opened outside the try so a failure to parse the archive still closes the window
        // onto the installer; ownership only transfers once OpenArchive succeeds.
        var inner = NsisArchive.Open(installer, blob, leaveOpen: true);

        try
        {
            archive = ArchiveFactory.OpenArchive(inner, new ReaderOptions { LeaveStreamOpen = false });
        }
        catch (InvalidOperationException)
        {
            inner.Dispose();
            warnings.Add("A packed archive inside the installer was in an unsupported format.");
            return 0;
        }
        catch (InvalidDataException)
        {
            inner.Dispose();
            warnings.Add("A packed archive inside the installer is corrupt.");
            return 0;
        }
        catch (IOException)
        {
            inner.Dispose();
            warnings.Add("A packed archive inside the installer could not be read.");
            return 0;
        }

        using (archive)
        {
            var considered = 0;
            var sawAsar = false;

            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (entry.IsDirectory || entry.Key is not { } key)
                {
                    continue;
                }

                if (!key.EndsWith(".asar", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (entry.Size > Limits.MaxFileBytes)
                {
                    warnings.Add(
                        $"An asar archive inside the installer exceeds "
                        + $"{Limits.MaxFileBytes / (1024 * 1024)} MB and was not read.");
                    continue;
                }

                if (Buffer(entry, cancellationToken) is not { } buffered)
                {
                    warnings.Add("An asar archive inside the installer could not be unpacked.");
                    continue;
                }

                using (buffered)
                {
                    sawAsar = true;
                    considered += ElectronRecoveryBackend.ReadAsarInto(
                        buffered, key, files, warnings, cancellationToken);
                }
            }

            if (!sawAsar)
            {
                warnings.Add(
                    "The installer's payload holds no application source this scanner can "
                    + "read. It is most likely a native application, which cannot be "
                    + "decompiled to anything analysable.");
            }

            return considered;
        }
    }

    /// <summary>
    /// Copies an entry into memory so the asar reader can seek within it, enforcing the
    /// budget during decompression rather than trusting the declared size.
    /// </summary>
    private static MemoryStream? Buffer(IArchiveEntry entry, CancellationToken cancellationToken)
    {
        try
        {
            using var source = entry.OpenEntryStream();
            var buffer = new MemoryStream();

            var chunk = new byte[81920];
            long written = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var read = source.Read(chunk, 0, chunk.Length);
                if (read == 0)
                {
                    break;
                }

                written += read;

                if (written > Limits.MaxFileBytes)
                {
                    buffer.Dispose();
                    return null;
                }

                buffer.Write(chunk, 0, read);
            }

            buffer.Position = 0;
            return buffer;
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            // SharpCompress raises this for codecs it does not implement.
            return null;
        }
    }

    /// <summary>
    /// Builds the coverage figure, keeping the distinction between "an installer we could not
    /// open", "an installer holding a native application", and "an installer we read".
    /// Collapsing those into one zero would be the coverage-honesty failure this tool exists
    /// to avoid.
    /// </summary>
    private static CoverageReport BuildCoverage(
        List<RecoveredFile> files,
        int considered,
        int payloads,
        int blobs,
        List<string> warnings)
    {
        var limitations = warnings.Distinct(StringComparer.Ordinal).Take(50).ToList();

        limitations.Add(
            "The installer's own script was not analysed. What it does to the machine during "
            + "installation, including any files it fetches, is outside what this scan covers.");

        string basis;

        if (blobs == 0)
        {
            basis = "This installer's payload could not be unpacked, so nothing inside it was read.";
        }
        else if (considered == 0)
        {
            basis = $"Unpacked {blobs} payload(s) from the installer, none of which contained "
                    + "readable application source.";
        }
        else
        {
            basis = $"Read {files.Count:N0} of {considered:N0} application files from inside the "
                    + $"installer, across {payloads} packed payload(s).";
        }

        return new CoverageReport
        {
            Percent = considered == 0
                ? 0
                : Math.Clamp((int)Math.Round(files.Count / (double)considered * 100), 0, 100),
            Basis = basis,
            RecoveredFileCount = files.Count,
            RecoveredBytes = files.Sum(f => (long)f.Content.Length),
            ChecksNotPossible = limitations,
        };
    }
}
