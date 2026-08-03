using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

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
        var findings = new List<Finding>();
        var budget = new DecompilationBudget();

        // No dependency manifest arrives with a loose payload, so assemblies are separated from
        // their framework by name until one turns up inside a bundle.
        var ownership = AssemblyOwnership.VendorList;
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

                var found = Read(
                    installer, blob, format, files, findings, warnings, budget, ref ownership,
                    cancellationToken);

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
            Findings = AssemblyInspector.Collapse(findings),
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
        List<Finding> findings,
        List<string> warnings,
        DecompilationBudget budget,
        ref AssemblyOwnership ownership,
        CancellationToken cancellationToken)
    {
        switch (format)
        {
            case "asar":
                return ReadAsarPayload(installer, blob, files, warnings, cancellationToken);

            case "7z" or "zip":
                return ReadNestedArchive(installer, blob, files, warnings, cancellationToken);

            case "pe":
                return ReadManagedPayload(
                    installer, blob, files, findings, warnings, budget, ref ownership,
                    cancellationToken);

            default:
                return 0;
        }
    }

    /// <summary>
    /// Reads an asar stored as a payload in its own right, rather than inside a nested archive.
    /// </summary>
    /// <remarks>
    /// Buffered rather than handed straight to the reader, and that is a fix rather than a
    /// preference. An asar's header is at the front and its file table gives offsets into the
    /// rest, so the reader asks the stream how long it is; a compressed payload arrives as a
    /// deflate stream, which answers that question by throwing. The nested-archive path buffers
    /// already and never hit it, and electron-builder puts the asar inside a nested archive, so
    /// the crash sat behind a layout that is legal, produced by other packers, and was never
    /// tested.
    /// </remarks>
    private static int ReadAsarPayload(
        Stream installer,
        NsisArchive.Blob blob,
        List<RecoveredFile> files,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        using var payload = Unpack(installer, blob, cancellationToken);

        if (payload is null)
        {
            warnings.Add("An asar archive inside the installer could not be unpacked.");
            return 0;
        }

        return ElectronRecoveryBackend.ReadAsarInto(
            payload, "the installer's asar archive", files, warnings, cancellationToken);
    }

    /// <summary>
    /// Copies one payload out of the installer into memory, or null when it cannot be read or
    /// runs past the budget.
    /// </summary>
    private static MemoryStream? Unpack(
        Stream installer,
        NsisArchive.Blob blob,
        CancellationToken cancellationToken)
    {
        try
        {
            using var source = NsisArchive.Open(installer, blob, leaveOpen: true);
            return Buffer(source, cancellationToken);
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

    /// <summary>
    /// Reads a .NET payload: either a single-file bundle carrying the whole application, or one
    /// assembly of a framework-dependent publish, which NSIS stores as its own payload per file.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Until this existed, an installer wrapping a .NET application reported nothing readable
    /// while the same executable dropped in on its own was decompiled in full. The recovery was
    /// already written; the installer simply never reached it, and the gap was invisible from
    /// the report because "an installer holding a native application" and "an installer holding
    /// an application we did not try to read" printed the same sentence.
    /// </para>
    /// <para>
    /// Buffered into memory first, because both the bundle reader and the decompiler seek and
    /// the payload arrives through a decompressing stream that cannot. It stays in memory: an
    /// installer's payload is the least trustworthy content this scanner handles and writing it
    /// out is exactly what the recovery layer promises not to do.
    /// </para>
    /// </remarks>
    private static int ReadManagedPayload(
        Stream installer,
        NsisArchive.Blob blob,
        List<RecoveredFile> files,
        List<Finding> findings,
        List<string> warnings,
        DecompilationBudget budget,
        ref AssemblyOwnership ownership,
        CancellationToken cancellationToken)
    {
        if (budget.Exhausted)
        {
            return 0;
        }

        var payload = Unpack(installer, blob, cancellationToken);

        if (payload is null)
        {
            return 0;
        }

        using (payload)
        {
            var before = files.Count;

            if (SingleFileBundle.IsBundle(payload))
            {
                payload.Position = 0;
                var entries = SingleFileBundle.Read(payload, warnings, cancellationToken);

                ownership = SingleFileRecoveryBackend.RecoverBundle(
                    entries, resolverBasePath: null, ownership, budget, files, findings, warnings,
                    cancellationToken);

                return files.Count - before;
            }

            if (ManagedName(payload) is not { } name)
            {
                // A native binary or an installer plugin. Not worth a warning of its own:
                // saying so for every helper DLL would bury the real limitations in noise.
                return 0;
            }

            // Named as the assembly names itself, so findings point at MyApp.dll rather than at
            // the position a blob happened to occupy in the installer.
            var label = name + ".dll";

            if (!ownership.IsApplicationCode(label))
            {
                return 0;
            }

            try
            {
                payload.Position = 0;

                ManagedAssemblyDecompiler.Decompile(
                    label, payload, resolverBasePath: null, budget, files, findings, warnings,
                    cancellationToken);
            }
            catch (BadImageFormatException)
            {
                warnings.Add($"{label} inside the installer is not a readable managed assembly.");
            }
            catch (InvalidDataException)
            {
                warnings.Add($"{label} inside the installer could not be unpacked.");
            }

            return files.Count - before;
        }
    }

    /// <summary>
    /// The assembly's own name, or null when the payload carries no managed metadata. Read
    /// before decompiling so a native payload costs one header read rather than a thrown
    /// exception per file.
    /// </summary>
    private static string? ManagedName(Stream payload)
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
                ? metadata.GetString(metadata.GetAssemblyDefinition().Name)
                : null;
        }
        catch (BadImageFormatException)
        {
            return null;
        }
        catch (InvalidDataException)
        {
            return null;
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
            return Buffer(source, cancellationToken);
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
    /// Copies a stream into memory, enforcing the budget during the copy rather than trusting
    /// a declared size.
    /// </summary>
    private static MemoryStream? Buffer(Stream source, CancellationToken cancellationToken)
    {
        try
        {
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
