using System.Reflection.PortableExecutable;

using Halation.Core.Artifacts;
using Halation.Core.Model;

namespace Halation.Core.Recovery;

/// <summary>
/// Recovers C# from loose managed assemblies using the ILSpy decompiler engine.
/// </summary>
/// <remarks>
/// This is the highest-fidelity path the scanner has. A managed assembly retains full
/// metadata, so the recovered C# is close enough to the original that source-level rules
/// behave much as they would on the real repository.
/// </remarks>
public sealed class DotNetRecoveryBackend : IRecoveryBackend
{
    /// <summary>
    /// Assembly name prefixes belonging to the .NET runtime and framework rather than to the
    /// application.
    /// </summary>
    /// <remarks>
    /// A self-contained publish ships the whole framework beside the application, so without
    /// this filter the scanner decompiles Microsoft's WPF and BCL code and reports its
    /// findings against the user's app. Observed in testing: a real self-contained WPF
    /// application produced 25 findings, every one of them in PresentationFramework or
    /// PresentationCore, including BinaryFormatter usage inside Microsoft's own clipboard
    /// implementation. The user can act on none of it, and it buried the application entirely.
    /// <para>
    /// Same reasoning that skips node_modules: report on what the developer wrote and ships,
    /// not on the platform underneath it.
    /// </para>
    /// </remarks>
    private static readonly string[] FrameworkAssemblyPrefixes =
    [
        "System.", "Microsoft.", "mscorlib", "netstandard", "WindowsBase",
        // Prefix rather than the individual assemblies: the list originally named
        // PresentationCore and PresentationFramework, and PresentationUI slipped through to
        // report a Microsoft help link as the application's own cleartext endpoint.
        "Presentation", "ReachFramework", "UIAutomation",
        "DirectWriteForwarder", "PenImc", "D3DCompiler", "vcruntime", "ucrtbase",
        "api-ms-win", "hostfxr", "hostpolicy", "clrjit", "coreclr", "clretwrc",
        "mscordaccore", "mscordbi", "msquic", "createdump", "WindowsFormsIntegration",
        "Accessibility", "wpfgfx", "SOS.NETCore",
    ];

    public bool CanHandle(ArtifactKind kind) => kind == ArtifactKind.DotNetAssembly;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        // A folder holds the application plus everything it ships; a single dropped file is
        // itself the subject and is always analysed.
        var ownership = artifact.IsDirectory
            ? AssemblyOwnership.ForDirectory(artifact.Path)
            : null;

        var assemblies = artifact.IsDirectory
            ? FindAssemblies(artifact.Path, ownership!)
            : [artifact.Path];

        var files = new List<RecoveredFile>();
        var findings = new List<Finding>();
        var notes = new List<string>();
        var budget = new DecompilationBudget();

        // Separately from the assemblies, because the launcher is not one. See FindLaunchers.
        if (artifact.IsDirectory)
        {
            findings.AddRange(
                FindLaunchers(artifact.Path, ownership!)
                    .Select(exe => ExecutableSignature.Check(exe, Display(artifact, exe)))
                    .OfType<Finding>());
        }
        else if (ExecutableSignature.Check(artifact.Path, artifact.Name) is { } unsigned)
        {
            findings.Add(unsigned);
        }

        foreach (var path in assemblies)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (budget.Exhausted)
            {
                break;
            }

            var label = Display(artifact, path);

            try
            {
                using var stream = File.OpenRead(path);

                ManagedAssemblyDecompiler.Decompile(
                    label, stream, path, budget, files, findings, notes, cancellationToken);
            }
            catch (BadImageFormatException)
            {
                notes.Add($"{label} is not a readable managed assembly.");
            }
            catch (IOException ex)
            {
                notes.Add($"{label} could not be read: {ex.Message}");
            }
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Findings = AssemblyInspector.Collapse(findings),
            Coverage = CoverageBuilder.Build(files, budget, notes, ownership),
        });
    }

    private static IReadOnlyList<string> FindAssemblies(string directory, AssemblyOwnership ownership)
    {
        try
        {
            return Directory
                .EnumerateFiles(directory, "*.*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                .Where(f => ownership.IsApplicationCode(f))
                .Where(IsManaged)
                .Take(200)
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

    /// <summary>
    /// The application's own executables, which the assembly list cannot contain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A .NET launcher is a native apphost with no managed metadata</b>, so
    /// <see cref="FindAssemblies"/> filters it out through <see cref="IsManaged"/> and the
    /// signature check never saw it. Measured: two real installed folders produced no VC-BIN-010
    /// at all while the equivalent single-file builds produced one. It is also the only file in
    /// the folder anybody would sign, and the only one a reader double-clicks.
    /// </para>
    /// <para>
    /// Top directory only. A launcher sits beside the assemblies by convention, and searching
    /// the whole tree would report on bundled tools the application merely carries, which is the
    /// same mistake <see cref="FrameworkAssemblyPrefixes"/> exists to avoid. Ownership still
    /// filters it, so a vendored third-party exe at the root does not count either.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<string> FindLaunchers(string directory, AssemblyOwnership ownership)
    {
        try
        {
            return Directory
                .EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly)
                .Where(ownership.IsApplicationCode)
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

    /// <summary>True for runtime and framework assemblies the application merely carries.</summary>
    public static bool IsFrameworkAssembly(string assemblyName) =>
        FrameworkAssemblyPrefixes.Any(prefix =>
            assemblyName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    private static bool IsManaged(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new PEReader(stream);
            return reader.HasMetadata;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static string Display(ArtifactDescriptor artifact, string path) =>
        artifact.IsDirectory
            ? Path.GetRelativePath(artifact.Path, path).Replace('\\', '/')
            : Path.GetFileName(path);
}

/// <summary>Builds the coverage report shared by the managed recovery backends.</summary>
internal static class CoverageBuilder
{
    public static CoverageReport Build(
        List<RecoveredFile> files,
        DecompilationBudget budget,
        List<string> notes,
        AssemblyOwnership? ownership = null)
    {
        var percent = budget.TypesSeen == 0
            ? 0
            : (int)Math.Round(budget.TypesRecovered / (double)budget.TypesSeen * 100);

        // How application code was told apart from its dependencies belongs in the report:
        // an inferred separation may have set aside something the application actually wrote.
        var separation = ownership is null
            ? string.Empty
            : $" Dependencies were separated from application code by {ownership.Method}"
              + (ownership.IsApproximate ? " (approximate)." : ".");

        // Said out loud, because otherwise the number is a lie by arithmetic: "decompiled 0 of
        // 2,400 types" reads as a decompiler that failed, when what happened is that it worked
        // and produced text with the names taken out.
        var scrambled = budget.TypesUnreadable == 0
            ? string.Empty
            : $" A further {budget.TypesUnreadable:N0} decompiled into text with the names "
              + "stripped by an obfuscator. Those are in the report and the rules still read "
              + "them for literal values, but nothing can follow what they do, so they are not "
              + "counted as covered.";

        return new CoverageReport
        {
            Percent = Math.Clamp(percent, 0, 100),
            Basis = budget.TypesSeen == 0
                ? "No managed types were found to decompile."
                : $"Decompiled {budget.TypesRecovered:N0} of {budget.TypesSeen:N0} "
                  + $"top-level types to C#.{separation}{scrambled}",
            RecoveredFileCount = files.Count,
            RecoveredBytes = files.Sum(f => (long)f.Content.Length),
            ChecksNotPossible = notes.Distinct(StringComparer.Ordinal).Take(50).ToList(),
        };
    }
}
