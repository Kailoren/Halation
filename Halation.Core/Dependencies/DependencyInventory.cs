using System.Text.Json;
using System.Text.RegularExpressions;

using Halation.Core.Recovery;

namespace Halation.Core.Dependencies;

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

                // A vendored manifest's ranges are not a gap. Every package it names is itself
                // sitting in node_modules with its own exact manifest, so counting these
                // resolved 149 packages and then reported the same 149 as unchecked.
                if (name.Equals("package.json", StringComparison.OrdinalIgnoreCase)
                    && !file.RelativePath.Replace('\\', '/')
                            .Contains("node_modules/", StringComparison.Ordinal)
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

        // Both of these bound what the resolved list means, and neither is visible from the
        // list itself, so they are stated rather than left for the reader to infer.
        if (found.Values.Any(d => d.DeclaredIn.Replace('\\', '/')
                .Contains("node_modules/", StringComparison.Ordinal)))
        {
            notes.Add(
                "Package versions were read from the bundled node_modules tree, which shows "
                + "what the application ships rather than what it loads. A package that is "
                + "bundled but never required is still listed.");

            notes.Add(
                "Any dependency moved out of the archive at build time, by asarUnpack or "
                + "similar, was not seen and is not included in this list.");
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
            "package.json" => ReadVendoredPackage(file),
            "requirements.txt" => ReadRequirements(file),

            // Lock files from the other ecosystems OSV already answers for. Each records what
            // was actually installed rather than what was asked for, which is the whole
            // difference between a dependency that can be checked and one that cannot.
            "pipfile.lock" => ReadPipfileLock(file),
            "yarn.lock" => ReadYarnLock(file),
            "pnpm-lock.yaml" => ReadPnpmLock(file),
            "go.sum" => ReadGoSum(file),
            "cargo.lock" => ReadTomlPackages(file, "crates.io"),
            "poetry.lock" => ReadTomlPackages(file, "PyPI"),
            "composer.lock" => ReadComposerLock(file),
            "gemfile.lock" => ReadGemfileLock(file),
            "gradle.lockfile" => ReadGradleLock(file),
            _ => [],
        };

    /// <summary>
    /// Strips the leading <c>v</c> some ecosystems carry and OSV does not want.
    /// </summary>
    /// <remarks>
    /// Go and Packagist both write <c>v1.2.3</c> in their lock files while OSV indexes them as
    /// <c>1.2.3</c>. Sent unstripped, every query returns nothing and the report says the
    /// packages are clean, which is the worst way for this to fail.
    /// </remarks>
    private static string NormaliseVersion(string version)
    {
        var trimmed = version.Trim().Trim('"');

        return trimmed.Length > 1 && trimmed[0] is 'v' or 'V' && char.IsDigit(trimmed[1])
            ? trimmed[1..]
            : trimmed;
    }

    /// <summary>
    /// Reads a Pipenv lock file.
    /// </summary>
    /// <remarks>
    /// Both sections, since a development dependency still ships in a great many projects.
    /// Versions are written as requirement specifiers, so an exact pin arrives as
    /// <c>"==2.25.1"</c>; anything looser, and any package pinned to a git reference rather
    /// than a release, names no version that can be checked and is skipped rather than guessed
    /// at. The <c>_meta</c> section is not a package list and is passed over by name.
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadPipfileLock(RecoveredFile file)
    {
        using var document = JsonDocument.Parse(file.Content);

        foreach (var section in new[] { "default", "develop" })
        {
            if (!document.RootElement.TryGetProperty(section, out var packages)
                || packages.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var package in packages.EnumerateObject())
            {
                if (package.Value.ValueKind != JsonValueKind.Object
                    || !package.Value.TryGetProperty("version", out var version)
                    || version.GetString() is not { Length: > 0 } specifier)
                {
                    continue;
                }

                var pinned = specifier.Trim();

                if (!pinned.StartsWith("==", StringComparison.Ordinal))
                {
                    continue;
                }

                pinned = pinned[2..].Trim();

                if (pinned.Length == 0)
                {
                    continue;
                }

                yield return new DependencyRef
                {
                    Ecosystem = "PyPI",
                    Name = package.Name,
                    Version = pinned,
                    DeclaredIn = file.RelativePath,
                };
            }
        }
    }

    /// <summary>
    /// Splits an npm specifier into its package name and the rest.
    /// </summary>
    /// <remarks>
    /// The separator is the last <c>@</c> rather than the first, because a scoped package
    /// begins with one: <c>@babel/core@^7.0.0</c> is the package <c>@babel/core</c>. Splitting
    /// on the first would query OSV for a package called nothing at version
    /// <c>babel/core@^7.0.0</c>.
    /// </remarks>
    private static string? NpmNameOf(string specifier)
    {
        var trimmed = specifier.Trim().Trim('"', '\'');
        var separator = trimmed.LastIndexOf('@');

        return separator > 0 ? trimmed[..separator] : null;
    }

    /// <summary>
    /// Reads a Yarn lock file, both the classic format and the Berry one.
    /// </summary>
    /// <remarks>
    /// The two differ in punctuation rather than in shape: classic writes
    /// <c>version "4.17.21"</c> and Berry writes <c>version: 4.17.21</c>, both indented under a
    /// header naming one or more specifiers. Taking the name from the header rather than from
    /// the resolution line keeps one reader for both.
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadYarnLock(RecoveredFile file)
    {
        string? name = null;

        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');

            if (line.Length == 0 || line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            // A header sits at the left margin and ends the previous entry.
            if (!char.IsWhiteSpace(line[0]))
            {
                // Several specifiers can share one entry; they resolve to the same package, so
                // the first names it.
                name = line.TrimEnd(':').Split(',')[0] is { Length: > 0 } specifier
                    ? NpmNameOf(specifier)
                    : null;

                continue;
            }

            var indented = line.Trim();

            if (name is null || !indented.StartsWith("version", StringComparison.Ordinal))
            {
                continue;
            }

            var version = indented["version".Length..].TrimStart(':', ' ').Trim().Trim('"');

            if (version.Length == 0 || !char.IsDigit(version[0]))
            {
                continue;
            }

            yield return new DependencyRef
            {
                Ecosystem = "npm",
                Name = name,
                Version = version,
                DeclaredIn = file.RelativePath,
            };

            name = null;
        }
    }

    /// <summary>
    /// Reads a pnpm lock file.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The package list is keyed by the package itself, so there is no version line to find:
    /// the key is the whole record. Its spelling has changed across versions, from
    /// <c>/lodash/4.17.21</c> through <c>/lodash@4.17.21</c> to a bare <c>lodash@4.17.21</c>,
    /// and a key can carry the peers it was built against in brackets. All four shapes are
    /// accepted, since a lock file in a project is whichever pnpm wrote it.
    /// </para>
    /// <para>
    /// Only the <c>packages</c> section is read. Later versions repeat everything under
    /// <c>snapshots</c>, which would double the list.
    /// </para>
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadPnpmLock(RecoveredFile file)
    {
        var inPackages = false;

        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');

            if (line.Length == 0 || line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            if (!char.IsWhiteSpace(line[0]))
            {
                inPackages = line.StartsWith("packages:", StringComparison.Ordinal);
                continue;
            }

            // Only the section's own keys, which sit one level in. Anything deeper is a
            // property of the package rather than another package.
            if (!inPackages || !line.EndsWith(':') || line.Length - line.TrimStart().Length != 2)
            {
                continue;
            }

            var key = line.Trim().TrimEnd(':').Trim('\'', '"');

            // Peer suffixes describe how it was built, not what it is.
            var bracket = key.IndexOf('(');
            if (bracket > 0)
            {
                key = key[..bracket];
            }

            key = key.TrimStart('/');

            // The v5 spelling separates with a slash; everything later uses an @.
            var separator = key.LastIndexOf('@');
            var name = separator > 0 ? key[..separator] : null;
            var version = separator > 0 ? key[(separator + 1)..] : null;

            if (name is null || version is null || version.Length == 0 || !char.IsDigit(version[0]))
            {
                var slash = key.LastIndexOf('/');

                if (slash <= 0 || slash == key.Length - 1 || !char.IsDigit(key[slash + 1]))
                {
                    continue;
                }

                name = key[..slash];
                version = key[(slash + 1)..];
            }

            yield return new DependencyRef
            {
                Ecosystem = "npm",
                Name = name,
                Version = version,
                DeclaredIn = file.RelativePath,
            };
        }
    }

    /// <summary>
    /// Reads a Go checksum file.
    /// </summary>
    /// <remarks>
    /// Lines are <c>module version hash</c>, with a second line per module ending
    /// <c>/go.mod</c> that hashes the manifest rather than the code. Only the first names a
    /// version that was built into the binary. go.sum rather than go.mod because it lists the
    /// full transitive set, which is where the vulnerable package usually is.
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadGoSum(RecoveredFile file)
    {
        foreach (var raw in file.Content.Split('\n'))
        {
            var parts = raw.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // Three fields is not enough to call something a checksum line: any sentence has
            // three words. The version has to look like one and the hash has to be labelled,
            // or a line of prose in the middle of the file becomes a package named "not"
            // at version "a".
            if (parts.Length < 3
                || parts[1].EndsWith("/go.mod", StringComparison.Ordinal)
                || parts[1].Length < 2
                || parts[1][0] != 'v'
                || !char.IsDigit(parts[1][1])
                || !parts[2].StartsWith("h1:", StringComparison.Ordinal))
            {
                continue;
            }

            yield return new DependencyRef
            {
                Ecosystem = "Go",
                Name = parts[0],
                Version = NormaliseVersion(parts[1]),
                DeclaredIn = file.RelativePath,
            };
        }
    }

    /// <summary>
    /// Reads the <c>[[package]]</c> tables that Cargo and Poetry both use.
    /// </summary>
    /// <remarks>
    /// One reader for two ecosystems because the file shape is identical: a repeated table with
    /// a name and a version. Parsed by hand rather than with a TOML library, since this is the
    /// only TOML either of them needs and a dependency added to read a dependency list is a
    /// poor trade.
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadTomlPackages(RecoveredFile file, string ecosystem)
    {
        string? name = null;

        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.Trim();

            if (line.StartsWith("[[", StringComparison.Ordinal))
            {
                // A new table starts, so anything half-read belongs to the previous one.
                name = null;
                continue;
            }

            if (line.StartsWith("name", StringComparison.Ordinal) && Value(line) is { } read)
            {
                name = read;
                continue;
            }

            if (name is null
                || !line.StartsWith("version", StringComparison.Ordinal)
                || Value(line) is not { Length: > 0 } version)
            {
                continue;
            }

            yield return new DependencyRef
            {
                Ecosystem = ecosystem,
                Name = name,
                Version = NormaliseVersion(version),
                DeclaredIn = file.RelativePath,
            };

            name = null;
        }

        static string? Value(string line)
        {
            var separator = line.IndexOf('=');

            return separator < 0 ? null : line[(separator + 1)..].Trim().Trim('"');
        }
    }

    /// <summary>Reads a Composer lock file, both the runtime and development sets.</summary>
    private static IEnumerable<DependencyRef> ReadComposerLock(RecoveredFile file)
    {
        using var document = JsonDocument.Parse(file.Content);

        foreach (var section in new[] { "packages", "packages-dev" })
        {
            if (!document.RootElement.TryGetProperty(section, out var packages)
                || packages.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var package in packages.EnumerateArray())
            {
                if (package.ValueKind != JsonValueKind.Object
                    || package.TryGetProperty("name", out var name) is false
                    || package.TryGetProperty("version", out var version) is false
                    || name.GetString() is not { Length: > 0 } packageName
                    || version.GetString() is not { Length: > 0 } packageVersion)
                {
                    continue;
                }

                yield return new DependencyRef
                {
                    Ecosystem = "Packagist",
                    Name = packageName,
                    Version = NormaliseVersion(packageVersion),
                    DeclaredIn = file.RelativePath,
                };
            }
        }
    }

    /// <summary>
    /// Reads a Bundler lock file.
    /// </summary>
    /// <remarks>
    /// Indentation carries the meaning here. Under <c>specs:</c>, a gem installed at an exact
    /// version sits at four spaces; its own requirements are listed under it at six, as ranges.
    /// Reading both would report <c>rspec-core (~&gt; 3.10.0)</c> as an installed version.
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadGemfileLock(RecoveredFile file)
    {
        var inSpecs = false;

        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');

            if (line.TrimEnd().EndsWith("specs:", StringComparison.Ordinal))
            {
                inSpecs = true;
                continue;
            }

            // Any line back at the left margin ends the section.
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                inSpecs = false;
                continue;
            }

            if (!inSpecs)
            {
                continue;
            }

            var match = GemSpec.Match(line);

            if (match.Success)
            {
                yield return new DependencyRef
                {
                    Ecosystem = "RubyGems",
                    Name = match.Groups["name"].Value,
                    Version = NormaliseVersion(match.Groups["version"].Value),
                    DeclaredIn = file.RelativePath,
                };
            }
        }
    }

    /// <summary>Exactly four spaces, so a gem's own requirements at six are not read as installs.</summary>
    private static readonly Regex GemSpec = new(
        @"^ {4}(?<name>[A-Za-z0-9_.\-]+) \((?<version>\d[^)~><=,]*)\)\s*$",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(2));

    /// <summary>
    /// Reads a Gradle lock file: <c>group:artifact:version=configurations</c> per line.
    /// </summary>
    private static IEnumerable<DependencyRef> ReadGradleLock(RecoveredFile file)
    {
        foreach (var raw in file.Content.Split('\n'))
        {
            var line = raw.Trim();

            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var coordinate = line.Split('=')[0];
            var parts = coordinate.Split(':');

            if (parts.Length < 3 || parts[2].Length == 0 || !char.IsDigit(parts[2][0]))
            {
                continue;
            }

            yield return new DependencyRef
            {
                // OSV names a Maven package by its group and artifact together.
                Ecosystem = "Maven",
                Name = $"{parts[0]}:{parts[1]}",
                Version = NormaliseVersion(parts[2]),
                DeclaredIn = file.RelativePath,
            };
        }
    }

    /// <summary>Reads an installed package's own manifest.</summary>
    /// <remarks>
    /// <para>
    /// A package.json in a source tree declares ranges and says nothing about what shipped,
    /// which is why it is otherwise treated as unresolved. One vendored under node_modules is
    /// a different document: it is the published manifest of the package actually sitting in
    /// the bundle, so its version is exact. For a shipped application that is stronger
    /// evidence than a lock file, which records only what was meant to be installed. It is
    /// also the only evidence there is, because electron-builder does not put a lock file
    /// inside the asar.
    /// </para>
    /// <para>
    /// The name is taken from the manifest rather than the directory so a scoped package
    /// keeps its <c>@scope/</c> prefix, but it must still agree with where the file sits.
    /// Packages ship internal manifests in subdirectories, and one real application vendors
    /// <c>node_modules/fast-uri/benchmark/package.json</c>, which declares the name
    /// "benchmark". Trusting the name alone would have reported a vulnerability in an npm
    /// package the application does not ship.
    /// </para>
    /// </remarks>
    private static IEnumerable<DependencyRef> ReadVendoredPackage(RecoveredFile file)
    {
        var normalised = file.RelativePath.Replace('\\', '/');
        var marker = normalised.LastIndexOf("node_modules/", StringComparison.Ordinal);

        // The application's own manifest is not one of its own dependencies.
        if (marker < 0)
        {
            yield break;
        }

        var afterMarker = normalised[(marker + "node_modules/".Length)..];
        var slash = afterMarker.LastIndexOf('/');

        if (slash <= 0)
        {
            yield break;
        }

        var installedAs = afterMarker[..slash];

        using var document = JsonDocument.Parse(file.Content);

        if (!document.RootElement.TryGetProperty("name", out var nameElement)
            || nameElement.GetString() is not { Length: > 0 } name
            || !document.RootElement.TryGetProperty("version", out var versionElement)
            || versionElement.GetString() is not { Length: > 0 } version
            || !string.Equals(installedAs, name, StringComparison.Ordinal)
            || !IsExactVersion(version))
        {
            yield break;
        }

        yield return new DependencyRef
        {
            Ecosystem = "npm",
            Name = name,
            Version = version,
            DeclaredIn = file.RelativePath,
        };
    }

    /// <summary>
    /// A published manifest should always carry a single concrete version, but this is
    /// untrusted input, and a range reaching OSV would be matched as though it were exact.
    /// </summary>
    private static bool IsExactVersion(string version) =>
        char.IsAsciiDigit(version[0])
        && !version.Any(c => c is '^' or '~' or '>' or '<' or '=' or '*' or '|' or ' ');

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
