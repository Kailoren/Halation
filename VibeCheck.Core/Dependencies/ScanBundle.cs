using System.Text.Json;
using System.Text.Json.Serialization;

namespace VibeCheck.Core.Dependencies;

/// <summary>
/// A self-contained record of what a live scan looked up, so the same artifact can be
/// re-checked later with no network.
/// </summary>
/// <remarks>
/// <para>
/// This exists for the workflow that matters most: scan normally, find something suspicious,
/// then move the sample to an isolated machine and examine it there. The isolated machine
/// needs the advisories for <em>this application's</em> dependencies, not the whole database,
/// which is the difference between a few kilobytes and well over a gigabyte.
/// </para>
/// <para>
/// The artifact hash is recorded so a bundle can be proven to belong to the sample it is
/// re-scanned against. A bundle from a different artifact is refused rather than silently
/// producing results that look authoritative.
/// </para>
/// </remarks>
public sealed record ScanBundle
{
    /// <summary>Format version, so a future reader can refuse what it does not understand.</summary>
    public int Version { get; init; } = 1;

    public required string ArtifactSha256 { get; init; }

    public required string ArtifactName { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Where the advisories came from originally, carried through to the offline report.</summary>
    public required VulnerabilityDataProvenance Provenance { get; init; }

    public required IReadOnlyList<DependencyRef> Dependencies { get; init; }

    public required IReadOnlyList<Advisory> Advisories { get; init; }

    /// <summary>Which advisory applies to which dependency, by coordinate and identifier.</summary>
    public required IReadOnlyList<BundleMatch> Matches { get; init; }

    public IReadOnlyList<string> NotChecked { get; init; } = [];

    private static readonly JsonSerializerOptions Format = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Builds a bundle from a completed live lookup.</summary>
    public static ScanBundle From(
        string artifactName,
        string artifactSha256,
        IReadOnlyList<DependencyRef> dependencies,
        VulnerabilityLookupResult lookup)
    {
        ArgumentNullException.ThrowIfNull(dependencies);
        ArgumentNullException.ThrowIfNull(lookup);

        return new ScanBundle
        {
            ArtifactName = artifactName,
            ArtifactSha256 = artifactSha256,
            CreatedAt = DateTimeOffset.Now,
            Provenance = lookup.Provenance,
            Dependencies = dependencies,
            Advisories = [.. lookup.Matches
                .Select(m => m.Advisory)
                .DistinctBy(a => a.Id, StringComparer.OrdinalIgnoreCase)],
            Matches = [.. lookup.Matches
                .Select(m => new BundleMatch(m.Dependency.Coordinate, m.Advisory.Id))],
            NotChecked = lookup.NotChecked,
        };
    }

    public void Save(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        File.WriteAllText(path, JsonSerializer.Serialize(this, Format));
    }

    /// <summary>Reads a bundle, returning null when the file is absent or unreadable.</summary>
    public static ScanBundle? Load(string path)
    {
        try
        {
            var bundle = JsonSerializer.Deserialize<ScanBundle>(File.ReadAllText(path), Format);

            // A bundle from a newer format may describe things this build would misread.
            return bundle?.Version is 1 ? bundle : null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Conventional name, so a bundle travels beside the sample it describes.</summary>
    public static string FileNameFor(string artifactName) =>
        $"{artifactName}.vibecheck-bundle.json";
}

/// <summary>One dependency-to-advisory link inside a bundle.</summary>
public sealed record BundleMatch(string Coordinate, string AdvisoryId);

/// <summary>
/// Answers from a bundle written by an earlier live scan, making no network calls.
/// </summary>
/// <remarks>
/// The bundle's artifact hash is checked against the artifact being scanned. A mismatch is
/// refused outright: silently reusing another artifact's advisories would produce a report
/// that looks thorough and describes something else entirely.
/// </remarks>
public sealed class ScanBundleVulnerabilitySource(ScanBundle bundle, string expectedSha256)
    : IVulnerabilitySource
{
    private readonly ScanBundle _bundle = bundle;
    private readonly string _expectedSha256 = expectedSha256;

    public bool RequiresNetwork => false;

    public Task<VulnerabilityLookupResult> LookupAsync(
        IReadOnlyList<DependencyRef> dependencies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        if (!string.Equals(_bundle.ArtifactSha256, _expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(VulnerabilityLookupResult.Unavailable(
                $"The offline data bundle describes a different artifact "
                + $"({_bundle.ArtifactName}), so it was not used. Dependencies were not checked."));
        }

        var advisories = _bundle.Advisories.ToDictionary(a => a.Id, StringComparer.OrdinalIgnoreCase);
        var byCoordinate = dependencies.ToDictionary(d => d.Coordinate, StringComparer.OrdinalIgnoreCase);

        var matches = new List<VulnerabilityMatch>();

        foreach (var match in _bundle.Matches)
        {
            if (byCoordinate.TryGetValue(match.Coordinate, out var dependency)
                && advisories.TryGetValue(match.AdvisoryId, out var advisory))
            {
                matches.Add(new VulnerabilityMatch(dependency, advisory));
            }
        }

        // Anything present now but absent from the bundle was never looked up, which is a
        // different statement from "it is clean".
        var unknown = dependencies
            .Where(d => !_bundle.Dependencies.Any(b =>
                string.Equals(b.Coordinate, d.Coordinate, StringComparison.OrdinalIgnoreCase)))
            .Select(d => $"{d.Coordinate} is not covered by the offline bundle.")
            .ToList();

        return Task.FromResult(new VulnerabilityLookupResult
        {
            Matches = [.. matches
                .OrderByDescending(m => m.Advisory.Severity)
                .ThenBy(m => m.Dependency.Coordinate, StringComparer.Ordinal)],
            Provenance = _bundle.Provenance with
            {
                Origin = VulnerabilityDataOrigin.ScanBundle,
                Source = $"{_bundle.Provenance.Source} (offline bundle)",
            },
            NotChecked = [.. _bundle.NotChecked, .. unknown],
        });
    }
}
