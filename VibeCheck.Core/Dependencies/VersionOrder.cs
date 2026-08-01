namespace VibeCheck.Core.Dependencies;

/// <summary>
/// Orders package version strings.
/// </summary>
/// <remarks>
/// <para>
/// Needed only by the offline mirror. The live path sends versions to OSV, which applies each
/// ecosystem's own comparison rules; offline, that comparison has to happen here.
/// </para>
/// <para>
/// This implements the shared core the mainstream schemes agree on: dot-separated segments,
/// numeric segments compared numerically, and a prerelease suffix ordering before its
/// release. That covers semver, NuGet and the common shape of PEP 440. It deliberately does
/// not attempt full per-ecosystem semantics such as PEP 440 epochs or NuGet's legacy
/// four-part rules, and callers treat an undecidable comparison as unchecked rather than
/// assuming the package is clean.
/// </para>
/// </remarks>
public static class VersionOrder
{
    /// <summary>
    /// Compares two versions, or returns null when the result would not be trustworthy.
    /// </summary>
    public static int? Compare(string left, string right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        if (!TrySplit(left, out var leftCore, out var leftPre)
            || !TrySplit(right, out var rightCore, out var rightPre))
        {
            return null;
        }

        var length = Math.Max(leftCore.Count, rightCore.Count);

        for (var i = 0; i < length; i++)
        {
            var a = i < leftCore.Count ? leftCore[i] : 0;
            var b = i < rightCore.Count ? rightCore[i] : 0;

            if (a != b)
            {
                return a.CompareTo(b);
            }
        }

        // A prerelease precedes the release it leads to: 1.0.0-rc1 is before 1.0.0.
        return (leftPre, rightPre) switch
        {
            (null, null) => 0,
            (null, _) => 1,
            (_, null) => -1,
            _ => ComparePrerelease(leftPre, rightPre),
        };
    }

    /// <summary>Splits a version into numeric segments plus an optional prerelease tag.</summary>
    private static bool TrySplit(string version, out List<long> core, out string? prerelease)
    {
        core = [];
        prerelease = null;

        var text = version.Trim();
        if (text.Length == 0)
        {
            return false;
        }

        // Build metadata never affects ordering.
        var plus = text.IndexOf('+');
        if (plus >= 0)
        {
            text = text[..plus];
        }

        var dash = text.IndexOf('-');
        if (dash >= 0)
        {
            prerelease = text[(dash + 1)..];
            text = text[..dash];
        }

        foreach (var segment in text.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!long.TryParse(segment, out var value))
            {
                // A non-numeric core segment means an ecosystem-specific scheme this does
                // not model; refuse rather than guess.
                return false;
            }

            core.Add(value);
        }

        return core.Count > 0;
    }

    private static int ComparePrerelease(string left, string right)
    {
        var leftParts = left.Split('.');
        var rightParts = right.Split('.');

        for (var i = 0; i < Math.Max(leftParts.Length, rightParts.Length); i++)
        {
            if (i >= leftParts.Length)
            {
                return -1;
            }

            if (i >= rightParts.Length)
            {
                return 1;
            }

            var numericLeft = long.TryParse(leftParts[i], out var a);
            var numericRight = long.TryParse(rightParts[i], out var b);

            var result = (numericLeft, numericRight) switch
            {
                (true, true) => a.CompareTo(b),
                // Numeric identifiers always have lower precedence than alphanumeric ones.
                (true, false) => -1,
                (false, true) => 1,
                _ => string.CompareOrdinal(leftParts[i], rightParts[i]),
            };

            if (result != 0)
            {
                return result;
            }
        }

        return 0;
    }
}
