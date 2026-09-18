using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Rules;

namespace Halation.Core.DeepPass;

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

    /// <summary>
    /// Ceiling on requests, which is what a file costs now that a large one takes several.
    /// </summary>
    /// <remarks>
    /// Twice the file ceiling. Files are no longer truncated at sixty thousand characters, so
    /// the file count stopped bounding the spend: one minified renderer bundle is two dozen
    /// requests on its own. This holds the worst case near where the file ceiling used to put
    /// it, and a pass that reaches it says so and reports the coverage it actually achieved
    /// rather than reading on quietly.
    /// </remarks>
    public const int DefaultMaxRequests = 80;

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
    /// How one file names another: a module specifier, an imported path, or a script the markup
    /// pulls in.
    /// </summary>
    /// <remarks>
    /// The group name repeats across the alternatives on purpose, so whichever one matched, the
    /// specifier lands in the same capture.
    /// </remarks>
    private static readonly Regex ModuleReference = PatternRule.Compile(
        """
        require\s*\(\s*["'](?<ref>[^"']+)["']
        |import\s*\(\s*["'](?<ref>[^"']+)["']
        |\bfrom\s+["'](?<ref>[^"']+)["']
        |\bimport\s+["'](?<ref>[^"']+)["']
        |importScripts\s*\(\s*["'](?<ref>[^"']+)["']
        |\b(?:src|href)\s*=\s*["'](?<ref>[^"']+)["']
        |@import\s+(?:url\()?\s*["'](?<ref>[^"']+)["']
        """,
        RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// Files that really do reach a flagged one. A crude call graph, deliberately: resolving
    /// real ones across decompiled C#, minified JavaScript and Python is a compiler's job, and
    /// being approximate here costs a few extra files rather than a wrong answer.
    /// </summary>
    /// <remarks>
    /// <b>Approximate is not the same as meaningless.</b> This used to count any file whose text
    /// contained the flagged file's stem anywhere. On an Electron application the flagged file
    /// was <c>index.cjs</c>, so every other file in the archive "called" it on the strength of
    /// the word "index", and the report said so in as many words. Script languages are matched on
    /// the specifier they would actually import, and everything else on a whole-word occurrence
    /// of the name, which for a decompiled assembly is the type it would have to mention.
    /// </remarks>
    private static IEnumerable<RecoveredFile> CallersOf(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<string> flaggedPaths)
    {
        var flagged = flaggedPaths
            .Select(p => (Path: p.Replace('\\', '/'), Stem: Path.GetFileNameWithoutExtension(p)))
            .ToList();

        var stems = flagged
            .Select(f => f.Stem)
            .Where(s => s.Length > 3)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var identifier = stems.Count == 0
            ? null
            : new Regex(
                @"\b(?:" + string.Join('|', stems.Select(Regex.Escape)) + @")\b",
                RegexOptions.CultureInvariant);

        foreach (var file in files)
        {
            if (flaggedPaths.Contains(file.RelativePath, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            var imports = file.Language
                is SourceLanguage.JavaScript or SourceLanguage.TypeScript
                or SourceLanguage.Markup or SourceLanguage.Json;

            if (imports
                ? ModuleReference.Matches(file.Content).Any(m => NamesOneOf(m, flagged))
                : identifier?.IsMatch(file.Content) == true)
            {
                yield return file;
            }
        }
    }

    /// <summary>Whether a specifier resolves to one of the flagged files.</summary>
    /// <remarks>
    /// Two ways to be sure enough. The specifier can end with the flagged file's own path, which
    /// settles it outright; or it can be a relative path whose last segment is the flagged file's
    /// name, which is what a sibling import looks like. A bare package specifier that happens to
    /// end in the same word, <c>lodash/index</c> against this application's own <c>index.js</c>,
    /// is neither.
    /// </remarks>
    private static bool NamesOneOf(Match match, IReadOnlyList<(string Path, string Stem)> flagged)
    {
        var specifier = match.Groups["ref"].Value.Split('?', '#')[0].Replace('\\', '/');

        if (specifier.Length == 0)
        {
            return false;
        }

        var trimmed = specifier.TrimStart('.', '/');
        var relative = specifier.StartsWith('.') || specifier.StartsWith('/');
        var leaf = Path.GetFileNameWithoutExtension(specifier);

        return flagged.Any(f =>
            (trimmed.Length > 0
             && (f.Path.Equals(trimmed, StringComparison.OrdinalIgnoreCase)
                 || f.Path.EndsWith('/' + trimmed, StringComparison.OrdinalIgnoreCase)))
            || (relative && leaf.Equals(f.Stem, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HandlesUntrustedInput(RecoveredFile file) =>
        UntrustedSurface.IsMatch(file.Content);
}
