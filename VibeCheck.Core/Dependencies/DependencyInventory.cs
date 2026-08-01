using System.Text.Json;
using System.Text.RegularExpressions;

using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.Dependencies;

/// <summary>
/// One resolved dependency, at the exact version shipped.
/// </summary>
public sealed record DependencyRef
{
    /// <summary>Ecosystem name as OSV expects it: NuGet, npm, PyPI, Maven, Go, crates.io.</summary>
    public required string Ecosystem { get; init; }

    public required string Name { get; init; }

    /// <summary>The exact resolved version. Ranges are never recorded here.</summary>
    public required string Version { get; init; }

    /// <summary>Manifest the dependency was read from, for the report.</summary>
    public required string DeclaredIn { get; init; }

    public string Coordinate => $"{Ecosystem}:{Name}@{Version}";
}

/// <summary>What an inventory pass found, including what it could not resolve.</summary>
public sealed record DependencyInventoryResult
{
    public required IReadOnlyList<DependencyRef> Dependencies { get; init; }

    /// <summary>
    /// Manifests that declared ranges rather than resolved versions, so the report can say
    /// which dependencies went unchecked instead of implying they passed.
    /// </summary>
    public IReadOnlyList<string> Unresolved { get; init; } = [];

    public IReadOnlyList<string> Notes { get; init; } = [];

    public static DependencyInventoryResult Empty { get; } = new() { Dependencies = [] };
}

/// <summary>
/// Builds the list of third-party packages an application ships, for vulnerability lookup.
/// </summary>
/// <remarks>
/// <para>
/// Only exactly-resolved versions are collected. A range such as <c>^4.17.0</c> cannot be
/// matched against an advisory, because which version actually shipped depends on when the
/// install ran. Recording a guess would produce findings that are wrong in both directions,
/// so ranges are reported as unresolved instead.
/// </para>
/// <para>
/// This runs over recovered files, so it works identically whether the manifests came from a
/// source tree, a published folder, an asar archive, or a single-file bundle.
/// </para>
/// </remarks>
public static class DependencyInventory
{
    /// <summary>Ceiling on packages collected, to bound both memory and lookup batches.</summary>
    private const int MaxDependencies = 5_000;

    public static DependencyInventoryResult Extract(IReadOnlyList<RecoveredFile> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        var found = new Dictionary<string, DependencyRef>(StringComparer.OrdinalIgnoreCase);
        var unresolved = new List<string>();
        var notes = new List<string>();

        foreach (var file in files)
        {
            if (found.Count >= MaxDependencies)
            {
                notes.Add($"Stopped after {MaxDependencies:N0} dependencies.");
                break;
            }

            var name = Path.GetFileName(file.RelativePath);

            try
            {
                foreach (var dependency in ReadManifest(name, file))
                {
                    found.TryAdd(dependency.Coordinate, dependency);
                }

                if (name.Equals("package.json", StringComparison.OrdinalIgnoreCase)
                    && DeclaresRanges(file.Content))
                {
                    unresolved.Add(file.RelativePath);
                }
            }
            catch (JsonException)
            {
                notes.Add($"{file.RelativePath} is not valid JSON and was skipped.");
            }
        }

        if (unresolved.Count > 0 && found.Count == 0)
        {
            notes.Add(
                "Only version ranges were found, with no lock file to say what actually "
                + "shipped, so no dependency could be checked.");
        }

        return new DependencyInventoryResult
        {
            Dependencies = [.. found.Values.OrderBy(d => d.Coordinate, StringComparer.Ordinal)],
            Unresolved = unresolved,
            Notes = notes,
        };
    }

    private static IEnumerable<DependencyRef> ReadManifest(string fileName, RecoveredFile file) =>
        fileName.ToLowerInvariant() switch
        {
            var n when n.EndsWith(".deps.json", StringComparison.Ordinal) =>
                ReadDotNetDeps(file),
            "packages.lock.json" => ReadNuGetLock(file),
            "package-lock.json" => ReadNpmLock(file),
            "requirements.txt" => ReadRequirements(file),
            _ => [],
        };

    /// <summary>
    /// Reads the .NET dependency manifest. Entries typed "package" came from NuGet at a
    /// resolved version; "project" entries are the application's own code.
    /// </summary>
    private static IEnumerable<DependencyRef> ReadDotNetDeps(RecoveredFile file)
    {
        using var document = JsonDocument.Parse(file.Content);

        if (!document.RootElement.TryGetProperty("libraries", out var libraries)
            || libraries.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        foreach (var library in libraries.EnumerateObject())
        {
            if (!library.Value.TryGetProperty("type", out var type)
                || !string.Equals(type.GetString(), "package", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var slash = library.Name.LastIndexOf('/');
            if (slash <= 0 || slash == library.Name.Length - 1)
            {
                continue;
            }

            yield return new DependencyRef
            {
                Ecosystem = "NuGet",
                Name = library.Name[..slash],
                Version = library.Name[(slash + 1)..],
                DeclaredIn = file.RelativePath,
            };
        }
    }

    /// <summary>Reads a NuGet lock file, which pins every transitive dependency.</summary>
    private static IEnumerable<DependencyRef> ReadNuGetLock(RecoveredFile file)
    {
        using var document = JsonDocument.Parse(file.Content);

        if (!document.RootElement.TryGetProperty("dependencies", out var frameworks)
            || frameworks.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        foreach (var framework in frameworks.EnumerateObject())
        {
            if (framework.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var package in framework.Value.EnumerateObject())
            {
                if (package.Value.TryGetProperty("resolved", out var resolved)
                    && resolved.GetString() is { Length: > 0 } version)
                {
                    yield return new DependencyRef
                    {
                        Ecosystem = "NuGet",
                        Name = package.Name,
                        Version = version,
                        DeclaredIn = file.RelativePath,
                    };
                }
            }
        }
    }

    /// <summary>
    /// Reads an npm lock file. Lockfile v2 and v3 use a flat "packages" map keyed by install
    /// path; v1 uses a nested "dependencies" tree.
    /// </summary>
    private static IEnumerable<DependencyRef> ReadNpmLock(RecoveredFile file)
    {
        using var document = JsonDocument.Parse(file.Content);
        var root = document.RootElement;

        if (root.TryGetProperty("packages", out var packages)
            && packages.ValueKind == JsonValueKind.Object)
        {
            foreach (var entry in packages.EnumerateObject())
            {
                // The empty key is the root project itself, not a dependency.
                if (entry.Name.Length == 0
                    || !entry.Value.TryGetProperty("version", out var version)
                    || version.GetString() is not { Length: > 0 } resolved)
                {
                    continue;
                }

                var marker = entry.Name.LastIndexOf("node_modules/", StringComparison.Ordinal);
                var name = marker >= 0
                    ? entry.Name[(marker + "node_modules/".Length)..]
                    : entry.Name;

                yield return new DependencyRef
                {
                    Ecosystem = "npm",
                    Name = name,
                    Version = resolved,
                    DeclaredIn = file.RelativePath,
                };
            }

            yield break;
        }

        if (root.TryGetProperty("dependencies", out var tree)
            && tree.ValueKind == JsonValueKind.Object)
        {
            foreach (var dependency in WalkLegacyNpmTree(tree, file.RelativePath))
            {
                yield return dependency;
            }
        }
    }

    /// <summary>Walks the nested v1 lock tree, bounded so a crafted file cannot recurse away.</summary>
    private static IEnumerable<DependencyRef> WalkLegacyNpmTree(JsonElement node, string declaredIn)
    {
        var pending = new Stack<(JsonElement Element, int Depth)>();
        pending.Push((node, 0));

        while (pending.Count > 0)
        {
            var (element, depth) = pending.Pop();

            if (depth > 32)
            {
                continue;
            }

            foreach (var entry in element.EnumerateObject())
            {
                if (entry.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (entry.Value.TryGetProperty("version", out var version)
                    && version.GetString() is { Length: > 0 } resolved)
                {
                    yield return new DependencyRef
                    {
                        Ecosystem = "npm",
                        Name = entry.Name,
                        Version = resolved,
                        DeclaredIn = declaredIn,
                    };
                }

                if (entry.Value.TryGetProperty("dependencies", out var nested)
                    && nested.ValueKind == JsonValueKind.Object)
                {
                    pending.Push((nested, depth + 1));
                }
            }
        }
    }

    /// <summary>
    /// Reads pinned Python requirements. Only <c>==</c> pins are usable; anything looser
    /// leaves the installed version undetermined.
    /// </summary>
    private static IEnumerable<DependencyRef> ReadRequirements(RecoveredFile file)
    {
        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.Trim();

            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('-'))
            {
                continue;
            }

            var match = PinnedRequirement.Match(line);
            if (match.Success)
            {
                yield return new DependencyRef
                {
                    Ecosystem = "PyPI",
                    Name = match.Groups["name"].Value,
                    Version = match.Groups["version"].Value,
                    DeclaredIn = file.RelativePath,
                };
            }
        }
    }

    /// <summary>True when a package.json pins nothing exactly, which is the normal case.</summary>
    private static bool DeclaresRanges(string content)
    {
        try
        {
            using var document = JsonDocument.Parse(content);

            foreach (var section in new[] { "dependencies", "devDependencies" })
            {
                if (document.RootElement.TryGetProperty(section, out var element)
                    && element.ValueKind == JsonValueKind.Object
                    && element.EnumerateObject().Any())
                {
                    return true;
                }
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static readonly Regex PinnedRequirement = new(
        """^(?<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*(?<version>[A-Za-z0-9._+!-]+)""",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(2));
}
