using System.Globalization;

namespace Halation.Core.Update;

/// <summary>
/// A version as it appears on a release tag, ordered the way semantic versioning orders them.
/// </summary>
/// <remarks>
/// <para>
/// Written rather than taken from a package, because the whole question this type answers is
/// "is the tag on GitHub newer than the build that is running", and getting that wrong in
/// either direction is bad: too eager and the application offers to replace itself with an
/// older build, too shy and an update nobody is told about is the same as no updater at all.
/// </para>
/// <para>
/// The one rule that is easy to miss and matters here: a prerelease sorts <i>below</i> the
/// release it leads to, so 0.1.0-beta is older than 0.1.0. Comparing the numbers alone would
/// call them equal and never offer the release that the beta was a run-up to.
/// </para>
/// </remarks>
public readonly record struct ReleaseVersion : IComparable<ReleaseVersion>
{
    private ReleaseVersion(int major, int minor, int patch, string prerelease)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        Prerelease = prerelease;
    }

    public int Major { get; }

    public int Minor { get; }

    public int Patch { get; }

    /// <summary>The suffix after the hyphen, or empty for a release.</summary>
    public string Prerelease { get; }

    public bool IsPrerelease => Prerelease.Length > 0;

    /// <summary>
    /// Reads a version from a tag or an assembly's informational version.
    /// </summary>
    /// <remarks>
    /// Tolerant on the way in by design. Tags are typed by hand and arrive as "v1.2.3",
    /// "1.2.3", "1.2" or "1.2.3-beta.2+abc1234"; refusing any of those would mean an update
    /// silently never being offered, which is the failure nobody notices.
    /// </remarks>
    public static bool TryParse(string? text, out ReleaseVersion version)
    {
        version = default;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var span = text.Trim();

        if (span.StartsWith('v') || span.StartsWith('V'))
        {
            span = span[1..];
        }

        // Build metadata never affects ordering, so it is dropped rather than carried.
        var plus = span.IndexOf('+');
        if (plus >= 0)
        {
            span = span[..plus];
        }

        var prerelease = string.Empty;
        var hyphen = span.IndexOf('-');
        if (hyphen >= 0)
        {
            prerelease = span[(hyphen + 1)..];
            span = span[..hyphen];
        }

        var parts = span.Split('.');
        if (parts.Length is 0 or > 3)
        {
            return false;
        }

        var numbers = new int[3];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
            {
                return false;
            }
        }

        version = new ReleaseVersion(numbers[0], numbers[1], numbers[2], prerelease);

        return true;
    }

    public int CompareTo(ReleaseVersion other)
    {
        var numeric = Major.CompareTo(other.Major);
        if (numeric != 0)
        {
            return numeric;
        }

        numeric = Minor.CompareTo(other.Minor);
        if (numeric != 0)
        {
            return numeric;
        }

        numeric = Patch.CompareTo(other.Patch);
        if (numeric != 0)
        {
            return numeric;
        }

        return ComparePrerelease(Prerelease, other.Prerelease);
    }

    /// <summary>
    /// Orders the suffix by the semantic versioning rules: having one at all sorts below having
    /// none, and otherwise the dot-separated identifiers are compared one at a time.
    /// </summary>
    private static int ComparePrerelease(string left, string right)
    {
        if (left.Length == 0 && right.Length == 0)
        {
            return 0;
        }

        // A release outranks any prerelease of the same numbers. This is the case that stops
        // 0.1.0-beta from being mistaken for 0.1.0.
        if (left.Length == 0)
        {
            return 1;
        }

        if (right.Length == 0)
        {
            return -1;
        }

        var leftParts = left.Split('.');
        var rightParts = right.Split('.');

        for (var i = 0; i < Math.Min(leftParts.Length, rightParts.Length); i++)
        {
            var leftNumeric = int.TryParse(
                leftParts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var leftNumber);
            var rightNumeric = int.TryParse(
                rightParts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var rightNumber);

            var comparison = (leftNumeric, rightNumeric) switch
            {
                // beta.2 after beta.10 is the mistake a string comparison makes here.
                (true, true) => leftNumber.CompareTo(rightNumber),

                // Numeric identifiers sort below alphanumeric ones.
                (true, false) => -1,
                (false, true) => 1,
                _ => string.CompareOrdinal(leftParts[i], rightParts[i]),
            };

            if (comparison != 0)
            {
                return comparison;
            }
        }

        // Everything shared matched, so the longer one is the more specific and later.
        return leftParts.Length.CompareTo(rightParts.Length);
    }

    public static bool operator <(ReleaseVersion left, ReleaseVersion right) =>
        left.CompareTo(right) < 0;

    public static bool operator >(ReleaseVersion left, ReleaseVersion right) =>
        left.CompareTo(right) > 0;

    public static bool operator <=(ReleaseVersion left, ReleaseVersion right) =>
        left.CompareTo(right) <= 0;

    public static bool operator >=(ReleaseVersion left, ReleaseVersion right) =>
        left.CompareTo(right) >= 0;

    public override string ToString() =>
        IsPrerelease
            ? $"{Major}.{Minor}.{Patch}-{Prerelease}"
            : $"{Major}.{Minor}.{Patch}";
}
