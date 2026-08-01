using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Running totals shared across every assembly in one scan, so the limits apply to the
/// artifact as a whole rather than resetting per file.
/// </summary>
public sealed class DecompilationBudget
{
    /// <summary>Ceiling on decompiled types, so a large application cannot stall the scan.</summary>
    public int MaxTypes { get; init; } = 4_000;

    /// <summary>Ceiling on total recovered characters, roughly 64 MB of source.</summary>
    public int MaxCharacters { get; init; } = 64 * 1024 * 1024;

    public int TypesSeen { get; private set; }

    public int TypesRecovered { get; private set; }

    public int CharactersRecovered { get; private set; }

    public bool Exhausted => TypesRecovered >= MaxTypes || CharactersRecovered >= MaxCharacters;

    internal void CountSeen() => TypesSeen++;

    internal void CountRecovered(int characters)
    {
        TypesRecovered++;
        CharactersRecovered += characters;
    }
}

/// <summary>
/// Decompiles managed assemblies to C#, from a file or from memory.
/// </summary>
/// <remarks>
/// Shared by the loose-assembly backend and the single-file bundle backend. The bundle case
/// has no path on disk, and extracting to one would break the guarantee that untrusted
/// content is never written to the filesystem, so everything here works from a stream.
/// </remarks>
public static class ManagedAssemblyDecompiler
{
    /// <summary>
    /// Decompiles one assembly, appending its types to <paramref name="files"/>.
    /// </summary>
    /// <param name="label">How the assembly is named in findings, e.g. "MyApp.dll".</param>
    /// <param name="stream">The assembly image. Ownership stays with the caller.</param>
    /// <param name="resolverBasePath">
    /// A path used to locate referenced assemblies. For a bundle there is nothing beside the
    /// launcher to find, so references stay unresolved; decompilation still succeeds, with
    /// slightly less precise type names.
    /// </param>
    public static void Decompile(
        string label,
        Stream stream,
        string? resolverBasePath,
        DecompilationBudget budget,
        List<RecoveredFile> files,
        List<Finding> findings,
        List<string> notes,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(notes);

        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);

        if (!peReader.HasMetadata)
        {
            notes.Add($"{label} contains no managed metadata.");
            return;
        }

        var metadata = peReader.GetMetadataReader();

        findings.AddRange(AssemblyInspector.Inspect(metadata, peReader, label));

        var settings = new DecompilerSettings(LanguageVersion.CSharp10_0)
        {
            // Analysis reads better as plain constructs; the sugar hides the sinks rules look
            // for, and none of it changes behaviour.
            UseSdkStyleProjectFormat = false,
            ShowXmlDocumentation = false,
            RemoveDeadCode = false,
            RemoveDeadStores = false,
        };

        using var peFile = new PEFile(label, peReader);
        var resolver = new UniversalAssemblyResolver(
            resolverBasePath ?? label,
            throwOnError: false,
            targetFramework: null);

        var decompiler = new CSharpDecompiler(peFile, resolver, settings);
        var assemblyFolder = Path.GetFileNameWithoutExtension(label);

        foreach (var handle in metadata.TypeDefinitions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (budget.Exhausted)
            {
                notes.Add("Stopped decompiling at the scanner's size limit.");
                return;
            }

            var definition = metadata.GetTypeDefinition(handle);

            // Nested types are emitted with their declaring type, so requesting them
            // separately would duplicate the same source.
            if (definition.IsNested)
            {
                continue;
            }

            var name = metadata.GetString(definition.Name);
            var ns = metadata.GetString(definition.Namespace);

            // Compiler infrastructure carries no user logic worth scanning.
            if (name.StartsWith('<'))
            {
                continue;
            }

            budget.CountSeen();

            string code;
            try
            {
                code = decompiler.DecompileTypeAsString(new FullTypeName(
                    string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // One unrepresentable type must not abort the assembly. It shows up as
                // reduced coverage rather than being silently dropped.
                notes.Add($"Could not decompile {ns}.{name}.");
                continue;
            }

            budget.CountRecovered(code.Length);

            files.Add(new RecoveredFile
            {
                RelativePath = BuildPath(assemblyFolder, ns, name),
                Content = code,
                Language = SourceLanguage.CSharp,
                IsDecompiled = true,
            });
        }
    }

    /// <summary>Namespaced path, so findings point at a recognisable location.</summary>
    private static string BuildPath(string assemblyFolder, string ns, string name)
    {
        var folder = string.IsNullOrEmpty(ns)
            ? assemblyFolder
            : $"{assemblyFolder}/{ns.Replace('.', '/')}";

        return $"{folder}/{name}.cs";
    }
}

/// <summary>
/// Observations that only the binary can answer: whether it is signed, and whether its names
/// have been stripped. Neither is visible once the source has been recovered.
/// </summary>
public static class AssemblyInspector
{
    public static IReadOnlyList<Finding> Inspect(
        MetadataReader metadata,
        PEReader peReader,
        string label)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(peReader);

        var findings = new List<Finding>();

        var header = peReader.PEHeaders.CorHeader;
        var strongNamed = header is not null && (header.Flags & CorFlags.StrongNameSigned) != 0;

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
                    + "which indicates an obfuscator. Obfuscation is legitimate in commercial "
                    + "software, but it also means the source-level checks in this report saw very "
                    + "little of what the application actually does.",
                Remediation =
                    "Treat the coverage figure on this report as the ceiling on how much was verified.",
                FilePath = label,
            });
        }

        return findings;
    }

    /// <summary>
    /// Collapses per-assembly signing findings into one.
    /// </summary>
    /// <remarks>
    /// An application built from a dozen projects produced a dozen identical "not strong-name
    /// signed" findings, which is one fact about the distribution repeated twelve times. It
    /// padded the list and pushed the findings that differ further down.
    /// </remarks>
    public static List<Finding> Collapse(List<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var signing = findings.Where(f => f.RuleId == "VC-BIN-001").ToList();
        if (signing.Count <= 1)
        {
            return findings;
        }

        var names = signing
            .Select(f => f.FilePath)
            .Where(p => !string.IsNullOrEmpty(p))
            .Take(6)
            .ToList();

        var summary = signing[0] with
        {
            Title = $"{signing.Count} assemblies are not strong-name signed",
            Description =
                $"{signing.Count} of the application's assemblies carry no strong name, so nothing "
                + "binds them to a publisher and a modified copy is indistinguishable from the "
                + $"original. Affected: {string.Join(", ", names)}"
                + (signing.Count > names.Count ? ", and others." : "."),
            FilePath = null,
        };

        return [.. findings.Where(f => f.RuleId != "VC-BIN-001"), summary];
    }

    /// <summary>
    /// Heuristic: obfuscators rename types to one or two characters, or to sequences that are
    /// not valid C# identifiers at all.
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
}
