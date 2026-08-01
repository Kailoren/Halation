using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Recovers C# from .NET single-file applications by unpacking the bundle appended to the
/// native launcher and decompiling the assemblies inside it.
/// </summary>
/// <remarks>
/// <para>
/// Without this, a single-file publish is a dead end: the launcher carries no managed
/// metadata of its own, so the application reads as an opaque native binary and none of its
/// code is analysed. Since single-file is a common way to ship a .NET desktop application,
/// that gap covered a large share of the artifacts this scanner exists to examine.
/// </para>
/// <para>
/// Assemblies are decompiled straight from memory. Extracting them to a temporary directory
/// would be simpler, and would also mean writing the contents of an untrusted binary to disk,
/// which is the one thing the recovery layer does not do.
/// </para>
/// </remarks>
public sealed class SingleFileRecoveryBackend : IRecoveryBackend
{
    public bool CanHandle(ArtifactKind kind) => kind == ArtifactKind.DotNetSingleFile;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var launchers = artifact.IsDirectory
            ? FindBundles(artifact.Path)
            : [artifact.Path];

        var files = new List<RecoveredFile>();
        var findings = new List<Finding>();
        var notes = new List<string>();
        var budget = new DecompilationBudget();
        var bundlesRead = 0;

        foreach (var launcher in launchers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (budget.Exhausted)
            {
                break;
            }

            var entries = SingleFileBundle.Read(launcher, notes, cancellationToken);
            if (entries.Count == 0)
            {
                continue;
            }

            bundlesRead++;

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (budget.Exhausted)
                {
                    break;
                }

                switch (entry.Type)
                {
                    case BundleFileType.Assembly:
                        DecompileEntry(entry, launcher, budget, files, findings, notes, cancellationToken);
                        break;

                    // The manifests are plain JSON and list every dependency with its exact
                    // version, which is what the dependency checks need.
                    case BundleFileType.DepsJson:
                    case BundleFileType.RuntimeConfigJson:
                        if (SafeArchive.DecodeText(entry.Content) is { } json)
                        {
                            files.Add(new RecoveredFile
                            {
                                RelativePath = entry.RelativePath,
                                Content = json,
                                Language = SourceLanguage.Json,
                            });
                        }

                        break;
                }
            }
        }

        if (bundlesRead == 0)
        {
            notes.Add("No readable single-file bundle was found in this artifact.");
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Findings = findings,
            Coverage = CoverageBuilder.Build(files, budget, notes),
        });
    }

    private static void DecompileEntry(
        SingleFileBundle.BundleEntry entry,
        string launcher,
        DecompilationBudget budget,
        List<RecoveredFile> files,
        List<Finding> findings,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        // Bundles carry the whole framework alongside the application, exactly as a
        // self-contained folder publish does, so the same exclusion applies.
        var name = Path.GetFileNameWithoutExtension(entry.RelativePath);
        if (DotNetRecoveryBackend.IsFrameworkAssembly(name))
        {
            return;
        }

        try
        {
            using var stream = new MemoryStream(entry.Content, writable: false);

            ManagedAssemblyDecompiler.Decompile(
                entry.RelativePath,
                stream,
                launcher,
                budget,
                files,
                findings,
                notes,
                cancellationToken);
        }
        catch (BadImageFormatException)
        {
            notes.Add($"{entry.RelativePath} is not a readable managed assembly.");
        }
        catch (InvalidDataException)
        {
            notes.Add($"{entry.RelativePath} could not be unpacked.");
        }
    }

    /// <summary>Finds bundled launchers in a published application folder.</summary>
    private static IReadOnlyList<string> FindBundles(string directory)
    {
        try
        {
            return Directory
                .EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly)
                .Where(SingleFileBundle.IsBundle)
                .Take(10)
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
