using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Recovers C# from managed assemblies using the ILSpy decompiler engine.
/// </summary>
/// <remarks>
/// This is the highest-fidelity path the scanner has. A managed assembly retains full
/// metadata, so the recovered C# is close enough to the original that source-level rules
/// behave much as they would on the real repository.
/// </remarks>
public sealed class DotNetRecoveryBackend : IRecoveryBackend
{
    /// <summary>Ceiling on decompiled types, so a huge assembly cannot stall the scan.</summary>
    private const int MaxTypes = 4_000;

    /// <summary>Ceiling on total recovered characters, roughly 64 MB of source.</summary>
    private const int MaxTotalChars = 64 * 1024 * 1024;

    public bool CanHandle(ArtifactKind kind) => kind == ArtifactKind.DotNetAssembly;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var assemblies = artifact.IsDirectory
            ? FindAssemblies(artifact.Path)
            : [artifact.Path];

        var files = new List<RecoveredFile>();
        var findings = new List<Finding>();
        var notes = new List<string>();
        var totalChars = 0;
        var typesSeen = 0;
        var typesRecovered = 0;

        foreach (var path in assemblies)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (totalChars >= MaxTotalChars || typesRecovered >= MaxTypes)
            {
                notes.Add("Stopped decompiling at the scanner's size limit.");
                break;
            }

            try
            {
                DecompileAssembly(
                    path,
                    artifact,
                    files,
                    findings,
                    notes,
                    ref totalChars,
                    ref typesSeen,
                    ref typesRecovered,
                    cancellationToken);
            }
            catch (BadImageFormatException)
            {
                notes.Add($"{Display(artifact, path)} is not a readable managed assembly.");
            }
            catch (IOException ex)
            {
                notes.Add($"{Display(artifact, path)} could not be read: {ex.Message}");
            }
        }

        var coverage = BuildCoverage(files, typesSeen, typesRecovered, notes);

        return Task.FromResult(new RecoveryResult
        {
            Files = files,
            Findings = findings,
            Coverage = coverage,
        });
    }

    private static void DecompileAssembly(
        string path,
        ArtifactDescriptor artifact,
        List<RecoveredFile> files,
        List<Finding> findings,
        List<string> notes,
        ref int totalChars,
        ref int typesSeen,
        ref int typesRecovered,
        CancellationToken cancellationToken)
    {
        using var stream = File.OpenRead(path);
        using var peReader = new PEReader(stream);

        if (!peReader.HasMetadata)
        {
            notes.Add($"{Display(artifact, path)} contains no managed metadata.");
            return;
        }

        var metadata = peReader.GetMetadataReader();
        var assemblyLabel = Display(artifact, path);

        findings.AddRange(InspectAssembly(metadata, peReader, assemblyLabel));

        var settings = new DecompilerSettings(LanguageVersion.CSharp10_0)
        {
            // Analysis reads better as plain constructs; the sugar hides the sinks rules
            // look for, and none of it changes behaviour.
            UseSdkStyleProjectFormat = false,
            ShowXmlDocumentation = false,
            RemoveDeadCode = false,
            RemoveDeadStores = false,
        };

        using var decompilerFile = new PEFile(path, peReader);
        var resolver = new UniversalAssemblyResolver(path, throwOnError: false, targetFramework: null);
        var decompiler = new CSharpDecompiler(decompilerFile, resolver, settings);

        foreach (var handle in metadata.TypeDefinitions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (totalChars >= MaxTotalChars || typesRecovered >= MaxTypes)
            {
                return;
            }

            var definition = metadata.GetTypeDefinition(handle);

            // Nested types come out with their declaring type, so requesting them
            // separately would duplicate the same source.
            if (definition.IsNested)
            {
                continue;
            }

            typesSeen++;

            var name = metadata.GetString(definition.Name);
            var ns = metadata.GetString(definition.Namespace);

            // Compiler infrastructure carries no user logic worth scanning.
            if (name.StartsWith("<", StringComparison.Ordinal))
            {
                continue;
            }

            string code;
            try
            {
                code = decompiler.DecompileTypeAsString(new FullTypeName(
                    string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // One unrepresentable type must not abort the assembly. It is recorded as
                // reduced coverage rather than swallowed.
                notes.Add($"Could not decompile {ns}.{name}.");
                continue;
            }

            totalChars += code.Length;
            typesRecovered++;

            files.Add(new RecoveredFile
            {
                RelativePath = BuildPath(artifact, path, ns, name),
                Content = code,
                Language = SourceLanguage.CSharp,
                IsDecompiled = true,
            });
        }
    }

    /// <summary>
    /// Observations only the binary can answer: whether it is signed and whether its names
    /// have been stripped. Neither is visible once the source has been recovered.
    /// </summary>
    private static IEnumerable<Finding> InspectAssembly(
        MetadataReader metadata,
        PEReader peReader,
        string label)
    {
        var findings = new List<Finding>();

        var header = peReader.PEHeaders.CorHeader;
        var strongNamed = header is not null
            && (header.Flags & CorFlags.StrongNameSigned) != 0;

        if (!strongNamed)
        {
            findings.Add(new Finding
            {
                RuleId = "VC-BIN-001",
                Title = "Assembly is not strong-name signed",
                Severity = Severity.Low,
                Category = FindingCategory.BinaryHygiene,
                Description =
                    $"{label} carries no strong name, so nothing binds the file to a publisher. "
                    + "A modified copy is indistinguishable from the original.",
                Remediation =
                    "Sign released builds, and prefer Authenticode signing for anything users download.",
                FilePath = label,
            });
        }

        if (LooksObfuscated(metadata))
        {
            findings.Add(new Finding
            {
                RuleId = "VC-BIN-002",
                Title = "Type names appear obfuscated",
                Severity = Severity.Medium,
                Category = FindingCategory.BinaryHygiene,
                Description =
                    $"Most type names in {label} are single characters or non-identifier sequences, "
                    + "which indicates an obfuscator. Obfuscation is legitimate in commercial software, "
                    + "but it also means the source-level checks in this report saw very little of "
                    + "what the application actually does.",
                Remediation =
                    "Treat the coverage figure on this report as the ceiling on how much was verified.",
                FilePath = label,
            });
        }

        return findings;
    }

    /// <summary>
    /// Heuristic: obfuscators rename types to one or two characters, or to sequences that
    /// are not valid C# identifiers at all.
    /// </summary>
    private static bool LooksObfuscated(MetadataReader metadata)
    {
        var total = 0;
        var suspicious = 0;

        foreach (var handle in metadata.TypeDefinitions)
        {
            var name = metadata.GetString(metadata.GetTypeDefinition(handle).Name);

            if (name.StartsWith('<'))
            {
                continue;
            }

            total++;

            if (name.Length <= 2 || name.Contains('#') || name.Any(c => c > 127))
            {
                suspicious++;
            }
        }

        return total >= 20 && suspicious > total * 0.6;
    }

    private static CoverageReport BuildCoverage(
        List<RecoveredFile> files,
        int typesSeen,
        int typesRecovered,
        List<string> notes)
    {
        var percent = typesSeen == 0
            ? 0
            : (int)Math.Round(typesRecovered / (double)typesSeen * 100);

        return new CoverageReport
        {
            Percent = Math.Clamp(percent, 0, 100),
            Basis = typesSeen == 0
                ? "No managed types were found to decompile."
                : $"Decompiled {typesRecovered:N0} of {typesSeen:N0} top-level types to C#.",
            RecoveredFileCount = files.Count,
            RecoveredBytes = files.Sum(f => (long)f.Content.Length),
            ChecksNotPossible = notes.Distinct(StringComparer.Ordinal).ToList(),
        };
    }

    /// <summary>
    /// Assembly name prefixes belonging to the .NET runtime and framework rather than to the
    /// application.
    /// </summary>
    /// <remarks>
    /// A self-contained publish ships the whole framework beside the application, so without
    /// this filter the scanner decompiles Microsoft's WPF and BCL code and reports its
    /// findings against the user's app. Observed in testing: scanning a real self-contained
    /// WPF application produced 25 findings, every one of them in PresentationFramework or
    /// PresentationCore, including BinaryFormatter usage inside Microsoft's own clipboard
    /// implementation. The user can act on none of it, and it buried the application entirely.
    /// <para>
    /// This is the same reasoning that skips node_modules: report on what the developer
    /// wrote and ships, not on the platform underneath it.
    /// </para>
    /// </remarks>
    private static readonly string[] FrameworkAssemblyPrefixes =
    [
        "System.", "Microsoft.", "mscorlib", "netstandard", "WindowsBase",
        "PresentationCore", "PresentationFramework", "ReachFramework", "UIAutomation",
        "DirectWriteForwarder", "PenImc", "D3DCompiler", "vcruntime", "ucrtbase",
        "api-ms-win", "hostfxr", "hostpolicy", "clrjit", "coreclr", "clretwrc",
        "mscordaccore", "mscordbi", "msquic", "createdump", "WindowsFormsIntegration",
        "Accessibility", "wpfgfx", "SOS.NETCore",
    ];

    private static IReadOnlyList<string> FindAssemblies(string directory)
    {
        try
        {
            return Directory
                .EnumerateFiles(directory, "*.*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                .Where(f => !IsFrameworkAssembly(Path.GetFileNameWithoutExtension(f)))
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

    /// <summary>Namespaced path so findings point at a recognisable location.</summary>
    private static string BuildPath(ArtifactDescriptor artifact, string assemblyPath, string ns, string name)
    {
        var assembly = Path.GetFileNameWithoutExtension(assemblyPath);
        var folder = string.IsNullOrEmpty(ns) ? assembly : $"{assembly}/{ns.Replace('.', '/')}";

        return $"{folder}/{name}.cs";
    }

    private static string Display(ArtifactDescriptor artifact, string path) =>
        artifact.IsDirectory
            ? Path.GetRelativePath(artifact.Path, path).Replace('\\', '/')
            : Path.GetFileName(path);
}
