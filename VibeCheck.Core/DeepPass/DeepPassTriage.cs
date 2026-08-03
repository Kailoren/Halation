using System.Text.RegularExpressions;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;

namespace VibeCheck.Core.DeepPass;

/// <summary>One file selected for the deep pass, and why.</summary>
public sealed record TriagedFile
{
    public required RecoveredFile File { get; init; }

    /// <summary>Why this file was selected, shown in the report so the choice is auditable.</summary>
    public required string Reason { get; init; }

    /// <summary>Findings the deterministic pass already has here, so the model is not asked to re-find them.</summary>
    public IReadOnlyList<Finding> KnownFindings { get; init; } = [];
}

/// <summary>
/// Chooses which recovered files the deep pass reads.
/// </summary>
/// <remarks>
/// Triage is by <b>attack surface</b>, not by where a rule matched: a hits-only pass could only
/// deepen findings that already exist, and both findings the rules missed on a real application
/// were in files with zero findings. Callers of a flagged file come too, since that one hop is
/// what makes reachability gradeable.
/// </remarks>
/// <summary>Which files were chosen, and how many were in the running.</summary>
public sealed record TriageResult
{
    public IReadOnlyList<TriagedFile> Selected { get; init; } = [];

    /// <summary>How many files qualified, before the ceiling on how many are sent.</summary>
    public int Qualified { get; init; }

    /// <summary>True when the ceiling, rather than the code, decided where to stop.</summary>
    public bool HitCeiling => Qualified > Selected.Count;
}

public static class DeepPassTriage
{
    /// <summary>Ceiling on files sent, so a large application cannot run away with the key holder's money.</summary>
    public const int DefaultMaxFiles = 40;

    /// <summary>Files above this are truncated rather than dropped, so a big file is still looked at.</summary>
    private const int MaxFileChars = 60_000;

    /// <summary>
    /// Calls that put data the application does not control into its hands, or hand its data
    /// to something outside it. A file doing none of these has no untrusted input to reason
    /// about and is not worth paying for.
    /// </summary>
    private static readonly Regex UntrustedSurface = PatternRule.Compile(
        """
        HttpClient|WebClient|HttpRequest|RestClient
        |\.(?:GetStringAsync|GetAsync|PostAsync|SendAsync|DownloadString|ReadAsStringAsync)\s*\(
        |Deserialize|JsonSerializer|JsonConvert|XmlSerializer|BinaryFormatter|DataContractSerializer
        |Process\.Start|ProcessStartInfo|ShellExecute
        |File\.(?:Read|Open|Write)|FileStream|StreamReader|Directory\.
        |SqlCommand|DbCommand|ExecuteReader|ExecuteNonQuery|CommandText
        |Socket|TcpListener|TcpClient|UdpClient|NamedPipe
        |Assembly\.Load|Activator\.CreateInstance|Type\.GetType
        |stackalloc|Marshal\.|unsafe\s|DllImport
        |fetch\s*\(|XMLHttpRequest|axios|require\s*\(|child_process|eval\s*\(|exec\s*\(
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// Selects the files to send, most relevant first.
    /// </summary>
    public static IReadOnlyList<TriagedFile> Select(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<Finding> findings,
        int maxFiles = DefaultMaxFiles) => Triage(files, findings, maxFiles).Selected;

    /// <summary>
    /// Selects the files to send, and says how many qualified before the ceiling was applied.
    /// </summary>
    /// <remarks>
    /// The two numbers matter separately. Reading 17 of 285 files because 17 was everything
    /// worth reading is a complete pass; reading 17 because a ceiling stopped it at 17 leaves
    /// candidates unexamined. Those are opposite facts about the same scan and the report has
    /// to be able to tell them apart, rather than printing one sentence that fits both and
    /// reads like a shortfall either way.
    /// </remarks>
    public static TriageResult Triage(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<Finding> findings,
        int maxFiles = DefaultMaxFiles)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(findings);

        var byPath = findings
            .Where(f => !string.IsNullOrEmpty(f.FilePath))
            .GroupBy(f => f.FilePath!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<Finding>)[.. g], StringComparer.OrdinalIgnoreCase);

        var selected = new Dictionary<string, TriagedFile>(StringComparer.OrdinalIgnoreCase);

        // 1. Files the deterministic pass already flagged. The model's job on these is to
        //    judge whether the finding is real and how far it reaches, not to rediscover it.
        foreach (var file in files.Where(f => byPath.ContainsKey(f.RelativePath)))
        {
            selected[file.RelativePath] = new TriagedFile
            {
                File = file,
                Reason = "a deterministic rule matched here",
                KnownFindings = byPath[file.RelativePath],
            };
        }

        // 2. Callers of anything flagged. This is the hop that turns "unbounded allocation"
        //    into "unbounded allocation reachable from a remote response".
        foreach (var file in CallersOf(files, [.. selected.Keys]))
        {
            if (!selected.ContainsKey(file.RelativePath))
            {
                selected[file.RelativePath] = new TriagedFile
                {
                    File = file,
                    Reason = "calls into a file that a rule matched",
                };
            }
        }

        // 3. Everything else that handles untrusted input, whether or not a rule fired.
        foreach (var file in files)
        {
            if (selected.ContainsKey(file.RelativePath) || !HandlesUntrustedInput(file))
            {
                continue;
            }

            selected[file.RelativePath] = new TriagedFile
            {
                File = file,
                Reason = "handles input the application does not control",
            };
        }

        // Flagged files first, then their callers, then the wider surface: if the budget runs
        // out, it should run out on the least likely candidates.
        var ranked = selected.Values
            .OrderBy(t => t.KnownFindings.Count > 0 ? 0 : t.Reason.StartsWith("calls", StringComparison.Ordinal) ? 1 : 2)
            .ThenByDescending(t => t.KnownFindings.Count)
            .ToList();

        return new TriageResult
        {
            Selected = [.. ranked.Take(maxFiles)],
            Qualified = ranked.Count,
        };
    }

    /// <summary>
    /// Files that name a flagged file's type. A crude call graph, deliberately: resolving
    /// real ones across decompiled C#, minified JavaScript and Python is a compiler's job,
    /// and being approximate here costs a few extra files rather than a wrong answer.
    /// </summary>
    private static IEnumerable<RecoveredFile> CallersOf(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<string> flaggedPaths)
    {
        var names = flaggedPaths
            .Select(p => Path.GetFileNameWithoutExtension(p))
            .Where(n => n.Length > 3)
            .ToHashSet(StringComparer.Ordinal);

        if (names.Count == 0)
        {
            yield break;
        }

        foreach (var file in files)
        {
            if (flaggedPaths.Contains(file.RelativePath, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (names.Any(n => file.Content.Contains(n, StringComparison.Ordinal)))
            {
                yield return file;
            }
        }
    }

    private static bool HandlesUntrustedInput(RecoveredFile file) =>
        UntrustedSurface.IsMatch(file.Content);

    /// <summary>Trims a file to what will be sent, so cost is predictable before the call.</summary>
    public static string Excerpt(RecoveredFile file)
    {
        ArgumentNullException.ThrowIfNull(file);

        return file.Content.Length <= MaxFileChars
            ? file.Content
            : file.Content[..MaxFileChars] + "\n\n// [truncated by VibeCheck at 60,000 characters]";
    }
}
