using System.Text.RegularExpressions;

namespace Halation.Core.Recovery;

/// <summary>
/// The comments a bundler leaves behind saying which parts of a file are somebody else's code.
/// </summary>
/// <remarks>
/// <para>
/// esbuild writes <c>//#region node_modules/fflate/esm/browser.js</c> above each library it
/// inlines and <c>//#endregion</c> below it. That is the only statement inside a bundle about
/// where its third-party code is, and two separate parts of this scanner need it: the deep pass,
/// which skips those regions rather than paying a model to read a published package, and the
/// dependency inventory, which has to report the libraries as present and unchecked instead of
/// treating the application as genuinely dependency-free.
/// </para>
/// <para>
/// <b>The marker carries a path and never a version.</b> Nothing in a bundle says which release
/// of fflate was compiled in, so nothing here tries to guess one. A version guessed from a
/// package name would be matched against advisories and produce findings that are wrong in both
/// directions, which is worse than the honest answer that these could not be checked.
/// </para>
/// </remarks>
public static class BundleMarkers
{
    /// <summary>Opens a region of inlined third-party code, capturing the package name.</summary>
    private static readonly Regex Start = new(
        @"^[ \t]*//[ \t]*#region[ \t]+node_modules/(?<name>@[^/\s]+/[^/\s]+|[^/\s]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Multiline);

    /// <summary>Any region marker, so nested ones can be counted rather than assumed away.</summary>
    private static readonly Regex AnyStart = new(
        @"^[ \t]*//[ \t]*#region\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex End = new(
        @"^[ \t]*//[ \t]*#endregion\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>The package this line opens a region for, or null when it opens none.</summary>
    public static string? PackageOpenedBy(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        var match = Start.Match(line);

        return match.Success ? match.Groups["name"].Value : null;
    }

    public static bool OpensAnyRegion(string line) => AnyStart.IsMatch(line);

    public static bool ClosesRegion(string line) => End.IsMatch(line);

    /// <summary>
    /// Every library a bundler inlined into this text, named once each and in order.
    /// </summary>
    public static IReadOnlyList<string> PackagesIn(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        // Cheapest possible rejection first. Most files carry no markers at all, and the whole
        // point of the check is that it runs over every recovered file including bundles of
        // more than a million characters.
        if (!content.Contains("#region", StringComparison.Ordinal))
        {
            return [];
        }

        var names = new List<string>();

        foreach (Match match in Start.Matches(content))
        {
            var name = match.Groups["name"].Value;

            if (!names.Contains(name, StringComparer.Ordinal))
            {
                names.Add(name);
            }
        }

        return names;
    }
}
