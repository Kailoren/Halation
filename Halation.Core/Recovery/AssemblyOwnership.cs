using System.Text.Json;

namespace Halation.Core.Recovery;

/// <summary>
/// Decides which assemblies in a distribution are the application's own code and which are
/// dependencies it merely ships.
/// </summary>
/// <remarks>
/// The .NET equivalent of skipping node_modules. Without it, results are dominated by other
/// people's libraries: of 48 findings on one real application, 37 were DirectX interop inside
/// SharpDX, none of it actionable by whoever shipped the app. Three strategies, strongest
/// first, with the one used recorded so an inferred separation is visible rather than
/// presented as certainty.
/// </remarks>
public sealed class AssemblyOwnership
{
    /// <summary>
    /// Name prefixes of widely used NuGet packages, for the last-resort strategy.
    /// </summary>
    /// <remarks>
    /// Never exhaustive, and deliberately used only to exclude. A name absent from this list
    /// is treated as the application's own, so an unknown package costs some noise rather
    /// than silently hiding the application.
    /// </remarks>
    private static readonly string[] KnownPackagePrefixes =
    [
        "Newtonsoft.", "NLog", "Serilog", "log4net", "AutoMapper", "Dapper", "RestSharp",
        "SharpDX", "ICSharpCode.", "SharpZipLib", "NetMQ", "AsyncIO", "CSCore", "NAudio",
        "Avalonia", "DynamicData", "ReactiveUI", "Splat", "Google.Protobuf", "Grpc.",
        "protobuf-net", "MathNet.", "SkiaSharp", "HarfBuzzSharp", "Svg.", "ClosedXML",
        "EPPlus", "iTextSharp", "PdfSharp", "HtmlAgilityPack", "AngleSharp", "Polly",
        "FluentValidation", "MediatR", "Castle.", "Autofac", "Ninject", "Moq", "xunit",
        "NUnit", "Nito.", "Markdown.Avalonia", "ColorTextBlock", "Tmds.", "MicroCom",
        "ExCSS", "LiveCharts", "OxyPlot", "ScottPlot", "ZstdSharp", "K4os.", "BouncyCastle",
        "SQLitePCLRaw", "Sentry", "CommandLine", "YamlDotNet", "MessagePack", "Humanizer",
        "Octokit", "Flurl", "MimeKit", "MailKit", "QRCoder", "ZXing", "OpenTK", "Silk.NET",
        "Vortice", "TerraFX", "StbImageSharp", "SixLabors", "Magick", "Emgu", "Accord.",
    ];

    private readonly HashSet<string>? _projectAssemblies;
    private readonly HashSet<string>? _assembliesWithSymbols;

    private AssemblyOwnership(
        string method,
        bool isApproximate,
        HashSet<string>? projectAssemblies = null,
        HashSet<string>? assembliesWithSymbols = null)
    {
        Method = method;
        IsApproximate = isApproximate;
        _projectAssemblies = projectAssemblies;
        _assembliesWithSymbols = assembliesWithSymbols;
    }

    /// <summary>How application code was separated from dependencies, for the report.</summary>
    public string Method { get; }

    /// <summary>True when the separation was inferred rather than read from a manifest.</summary>
    public bool IsApproximate { get; }

    /// <summary>
    /// True when the assembly holds code the application's authors wrote.
    /// </summary>
    public bool IsApplicationCode(string assemblyName)
    {
        ArgumentNullException.ThrowIfNull(assemblyName);

        var name = Path.GetFileNameWithoutExtension(assemblyName);

        if (DotNetRecoveryBackend.IsFrameworkAssembly(name))
        {
            return false;
        }

        // A manifest listing the projects in the build is authoritative.
        if (_projectAssemblies is not null)
        {
            return _projectAssemblies.Contains(name);
        }

        // Build output ships symbols; packages restored from NuGet generally do not. The
        // name check still applies on top, because some distributions ship symbols for their
        // dependencies too: OpenTK and AsyncIO both arrived with a .pdb and were attributed
        // to the application until this was combined rather than used as a fallback.
        if (_assembliesWithSymbols is not null)
        {
            return _assembliesWithSymbols.Contains(name) && !IsKnownPackage(name);
        }

        return !IsKnownPackage(name);
    }

    private static bool IsKnownPackage(string name) =>
        KnownPackagePrefixes.Any(prefix =>
            name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>Chooses the best available strategy for a published folder.</summary>
    public static AssemblyOwnership ForDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        try
        {
            var depsFiles = Directory
                .EnumerateFiles(directory, "*.deps.json", SearchOption.AllDirectories)
                .Take(5)
                .ToList();

            foreach (var deps in depsFiles)
            {
                if (FromDepsJson(File.ReadAllText(deps)) is { } ownership)
                {
                    return ownership;
                }
            }

            var symbols = Directory
                .EnumerateFiles(directory, "*.pdb", SearchOption.AllDirectories)
                .Select(Path.GetFileNameWithoutExtension)
                .Where(n => !string.IsNullOrEmpty(n))
                .Select(n => n!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Only trust symbols when there are enough of them to look like build output;
            // one stray .pdb would otherwise exclude the entire application.
            if (symbols.Count >= 3)
            {
                return new AssemblyOwnership(
                    $"matched {symbols.Count} debug symbol files to application assemblies",
                    isApproximate: true,
                    assembliesWithSymbols: symbols);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return VendorList;
    }

    /// <summary>
    /// Reads the dependency manifest .NET writes beside a published application. Entries
    /// typed "project" are what the build compiled; "package" entries came from NuGet.
    /// </summary>
    public static AssemblyOwnership? FromDepsJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        try
        {
            using var document = JsonDocument.Parse(json);

            if (!document.RootElement.TryGetProperty("libraries", out var libraries)
                || libraries.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var projects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var library in libraries.EnumerateObject())
            {
                if (!library.Value.TryGetProperty("type", out var type)
                    || !string.Equals(type.GetString(), "project", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Keys are "Name/Version".
                var slash = library.Name.IndexOf('/');
                projects.Add(slash > 0 ? library.Name[..slash] : library.Name);
            }

            return projects.Count == 0
                ? null
                : new AssemblyOwnership(
                    $"read {projects.Count} application assemblies from the dependency manifest",
                    isApproximate: false,
                    projectAssemblies: projects);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Fallback when nothing better is available.</summary>
    public static AssemblyOwnership VendorList { get; } = new(
        "excluded recognised third-party libraries by name",
        isApproximate: true);
}
