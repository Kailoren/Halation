namespace Halation.Core.Dependencies;

/// <summary>
/// Computes a CVSS v3 base score from its vector string.
/// </summary>
/// <remarks>
/// Advisories publish the vector (<c>CVSS:3.1/AV:N/AC:L/...</c>) rather than the number, and
/// severity drives both the finding's rank and the overall score cap, so deriving it properly
/// matters. The formula is from the CVSS v3.1 specification; anything unparseable returns
/// null so the caller falls back to the publisher's own rating instead of inventing a score.
/// </remarks>
public static class Cvss
{
    public static double? TryComputeBaseScore(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:3", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var metrics = ParseMetrics(vector);

        if (!metrics.TryGetValue("AV", out var av) || !metrics.TryGetValue("AC", out var ac)
            || !metrics.TryGetValue("PR", out var pr) || !metrics.TryGetValue("UI", out var ui)
            || !metrics.TryGetValue("S", out var scope) || !metrics.TryGetValue("C", out var c)
            || !metrics.TryGetValue("I", out var i) || !metrics.TryGetValue("A", out var a))
        {
            return null;
        }

        var scopeChanged = scope == "C";

        var attackVector = av switch
        {
            "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => -1,
        };
        var attackComplexity = ac switch { "L" => 0.77, "H" => 0.44, _ => -1 };

        // Privileges Required is scored differently when the scope changes.
        var privileges = pr switch
        {
            "N" => 0.85,
            "L" => scopeChanged ? 0.68 : 0.62,
            "H" => scopeChanged ? 0.50 : 0.27,
            _ => -1,
        };
        var userInteraction = ui switch { "N" => 0.85, "R" => 0.62, _ => -1 };

        var confidentiality = Impact(c);
        var integrity = Impact(i);
        var availability = Impact(a);

        if (attackVector < 0 || attackComplexity < 0 || privileges < 0 || userInteraction < 0
            || confidentiality < 0 || integrity < 0 || availability < 0)
        {
            return null;
        }

        var subScore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));

        var impact = scopeChanged
            ? (7.52 * (subScore - 0.029)) - (3.25 * Math.Pow(subScore - 0.02, 15))
            : 6.42 * subScore;

        if (impact <= 0)
        {
            return 0;
        }

        var exploitability = 8.22 * attackVector * attackComplexity * privileges * userInteraction;

        var raw = scopeChanged
            ? Math.Min(1.08 * (impact + exploitability), 10)
            : Math.Min(impact + exploitability, 10);

        return RoundUp(raw);
    }

    private static double Impact(string metric) => metric switch
    {
        "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => -1,
    };

    /// <summary>
    /// The specification's roundup: to one decimal place, always upward.
    /// </summary>
    private static double RoundUp(double value)
    {
        var scaled = (int)Math.Round(value * 100_000, MidpointRounding.AwayFromZero);

        return scaled % 10_000 == 0
            ? scaled / 100_000.0
            : ((Math.Floor(scaled / 10_000.0) + 1) / 10.0);
    }

    private static Dictionary<string, string> ParseMetrics(string vector)
    {
        var metrics = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var part in vector.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = part.IndexOf(':');
            if (colon > 0 && colon < part.Length - 1)
            {
                metrics[part[..colon].ToUpperInvariant()] = part[(colon + 1)..].ToUpperInvariant();
            }
        }

        return metrics;
    }
}
