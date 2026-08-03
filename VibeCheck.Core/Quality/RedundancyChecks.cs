using System.Security.Cryptography;
using System.Text;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.Quality;

/// <summary>What the redundancy pass found, and what it deliberately did not look at.</summary>
public sealed record RedundancyResult
{
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>
    /// What the pass could not or would not examine. Never empty when files were skipped: a
    /// duplication report that silently ignored two thirds of an application would read as a
    /// clean bill of health for code it never compared.
    /// </summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

/// <summary>
/// Looks for repetition and dead weight in recovered source.
/// </summary>
/// <remarks>
/// <b>Decompiled files are excluded, and that is the whole design.</b> Decompilation
/// manufactures duplication nobody wrote: state machines, display classes, generics repeated
/// per type argument. A duplication report over that would be describing the compiler. So this
/// runs on verbatim text only, and the report says which it did. Everything here is
/// informational, because repetition is a maintenance cost rather than a risk.
/// </remarks>
public static class RedundancyChecks
{
    /// <summary>
    /// Consecutive significant lines that must match before a repeat is worth reporting.
    /// </summary>
    /// <remarks>
    /// Eight rather than a handful, and measured rather than guessed. Across 87 files of
    /// hand-written source a window of five produced 33 matches that were all ordinary
    /// language boilerplate; eight produced exactly one real duplicate and nothing else; ten
    /// and twelve produced nothing at all and missed the real one. So eight is the point where
    /// this stops reporting the shape of the language and starts reporting the author.
    /// </remarks>
    private const int MinimumBlockLines = 8;

    /// <summary>Files below this are too small for repetition to say anything.</summary>
    private const int MinimumFileLines = 10;

    /// <summary>Consecutive commented-out code lines before it counts as an abandoned block.</summary>
    private const int MinimumCommentedBlock = 6;

    /// <summary>
    /// Ceiling on reported groups, per check. A generated application can contain hundreds of
    /// repeats and a report listing all of them is not read at all. What was dropped is stated
    /// rather than silently truncated.
    /// </summary>
    private const int MaxReported = 10;

    /// <summary>Guards against pathological input; the pass is O(lines) but not free.</summary>
    private const int MaxTotalLines = 400_000;

    public static RedundancyResult Run(IReadOnlyList<RecoveredFile> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        var limitations = new List<string>();

        // Verbatim text only. See the class remarks: decompiled output invents repetition.
        var readable = files
            .Where(f => !f.IsDecompiled && IsCode(f.Language))
            .ToList();

        var decompiled = files.Count(f => f.IsDecompiled);

        if (decompiled > 0)
        {
            limitations.Add(
                $"{decompiled:N0} of {files.Count:N0} files were reconstructed by a decompiler "
                + "and were left out of the duplication check. Decompilers generate repetition "
                + "the author never wrote, so any result over them would describe the compiler "
                + "rather than the code.");
        }

        if (readable.Count == 0)
        {
            // Two different reasons for the same silence, and saying the wrong one is a small
            // lie about what the scan had in front of it. An artifact can yield verbatim files
            // that are all configuration and markup, which is not the same as yielding none.
            var verbatim = files.Count(f => !f.IsDecompiled);

            limitations.Add(verbatim == 0
                ? "No original source was available, so nothing was checked for duplication or "
                  + "dead weight."
                : $"None of the {verbatim:N0} verbatim file{(verbatim == 1 ? "" : "s")} recovered "
                  + "were code, so nothing was checked for duplication or dead weight.");

            return new RedundancyResult { Limitations = limitations };
        }

        var findings = new List<Finding>();

        findings.AddRange(DuplicateFiles(readable, limitations));
        findings.AddRange(DuplicateBlocks(readable, limitations));
        findings.AddRange(CommentedOutCode(readable, limitations));

        limitations.Add(
            $"Duplication and dead weight were checked across {readable.Count:N0} original "
            + "source files. These findings are informational: they describe maintenance cost "
            + "rather than risk, and none of them affects the score.");

        return new RedundancyResult { Findings = findings, Limitations = limitations };
    }

    // ---- Whole files that are copies of each other -------------------------

    private static IEnumerable<Finding> DuplicateFiles(
        IReadOnlyList<RecoveredFile> files,
        List<string> limitations)
    {
        var groups = files
            .Where(f => Significant(f.Content).Count >= MinimumFileLines)
            .GroupBy(f => Hash(string.Join('\n', Significant(f.Content))), StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .OrderByDescending(g => g.Count())
            .ToList();

        if (groups.Count > MaxReported)
        {
            limitations.Add(
                $"{groups.Count - MaxReported:N0} further group{(groups.Count - MaxReported == 1 ? "" : "s")} "
                + "of identical files were found and not listed individually.");
        }

        foreach (var group in groups.Take(MaxReported))
        {
            var paths = group.Select(f => f.RelativePath).Order(StringComparer.Ordinal).ToList();

            yield return new Finding
            {
                RuleId = "VC-DUP-001",
                Title = $"{paths.Count} identical copies of the same file",
                Severity = Severity.Info,
                UserSeverity = Severity.Info,
                Category = FindingCategory.Maintainability,
                Source = FindingSource.Rule,
                Description =
                    $"These {paths.Count} files have identical content once blank lines and "
                    + "trailing whitespace are ignored. Changing the behaviour means changing "
                    + "every copy, and a fix applied to one of them silently leaves the others "
                    + "as they were.",
                UserDescription =
                    "The application ships the same file more than once. That is untidy rather "
                    + "than unsafe, and there is nothing for you to do about it.",
                Evidence = string.Join("\n", paths),
                Remediation =
                    "Keep one copy and import it from the others, or delete the ones that are "
                    + "no longer referenced.",
                FilePath = paths[0],
            };
        }
    }

    // ---- Blocks repeated across or within files ----------------------------

    private static IEnumerable<Finding> DuplicateBlocks(
        IReadOnlyList<RecoveredFile> files,
        List<string> limitations)
    {
        // Windowed over significant lines only, so the imports and closing braces that every
        // file shares cannot masquerade as duplicated logic.
        var windows = new Dictionary<string, List<(string Path, int Line, string Text)>>(
            StringComparer.Ordinal);

        var budget = MaxTotalLines;

        foreach (var file in files)
        {
            var lines = SignificantWithNumbers(file.Content);

            if (lines.Count < MinimumBlockLines)
            {
                continue;
            }

            budget -= lines.Count;

            if (budget < 0)
            {
                limitations.Add(
                    "The application was too large to compare in full, so the duplication check "
                    + "stopped early. Files after that point were not compared.");
                break;
            }

            for (var i = 0; i + MinimumBlockLines <= lines.Count; i++)
            {
                var slice = lines.Skip(i).Take(MinimumBlockLines).ToList();
                var text = string.Join('\n', slice.Select(l => l.Text));
                var key = Hash(text);

                if (!windows.TryGetValue(key, out var seen))
                {
                    windows[key] = seen = [];
                }

                seen.Add((file.RelativePath, slice[0].Number, text));
            }
        }

        var groups = windows.Values
            .Where(v => v.Count > 1)

            // One copied function produces a run of overlapping windows that all match. Keeping
            // the first occurrence per file pair collapses that run into the one finding it
            // actually is.
            .GroupBy(v => string.Join("|", v.Select(x => x.Path).Distinct().Order(StringComparer.Ordinal)))
            .Select(g => g.OrderByDescending(v => v.Count).First())
            .OrderByDescending(v => v.Count)
            .ToList();

        if (groups.Count > MaxReported)
        {
            limitations.Add(
                $"{groups.Count - MaxReported:N0} further repeated block"
                + $"{(groups.Count - MaxReported == 1 ? " was" : "s were")} found and not listed "
                + "individually.");
        }

        foreach (var group in groups.Take(MaxReported))
        {
            var places = group
                .GroupBy(x => x.Path, StringComparer.Ordinal)
                .Select(g => $"{g.Key}:{g.First().Line}")
                .Order(StringComparer.Ordinal)
                .ToList();

            var within = places.Count == 1;

            yield return new Finding
            {
                RuleId = "VC-DUP-002",
                Title = within
                    ? $"A block of {MinimumBlockLines}+ lines repeats within one file"
                    : $"A block of {MinimumBlockLines}+ lines repeats across {places.Count} files",
                Severity = Severity.Info,
                UserSeverity = Severity.Info,
                Category = FindingCategory.Maintainability,
                Source = FindingSource.Rule,
                Description =
                    $"The same {MinimumBlockLines} or more lines of logic appear in "
                    + $"{group.Count} places. Copy-paste is the usual cause, and the risk it "
                    + "carries is that a correction made in one copy does not reach the others, "
                    + "which is how a bug that was fixed comes back.",
                UserDescription =
                    "The same code is written out several times over. That makes the application "
                    + "harder to maintain but is not something that affects you.",
                Evidence = Excerpt(group[0].Text),
                Remediation =
                    "Extract the repeated block into one function and call it from each place.",
                FilePath = group[0].Path,
                Line = group[0].Line,
            };
        }
    }

    // ---- Code left behind in comments --------------------------------------

    private static IEnumerable<Finding> CommentedOutCode(
        IReadOnlyList<RecoveredFile> files,
        List<string> limitations)
    {
        var found = new List<(string Path, int Line, int Length, string Text)>();

        foreach (var file in files)
        {
            var lines = file.Content.Split('\n');
            var run = new List<string>();
            var start = 0;

            for (var i = 0; i <= lines.Length; i++)
            {
                var stripped = i < lines.Length ? StripComment(lines[i]) : null;

                if (stripped is not null && LooksLikeCode(stripped))
                {
                    if (run.Count == 0)
                    {
                        start = i + 1;
                    }

                    run.Add(stripped);
                    continue;
                }

                if (run.Count >= MinimumCommentedBlock)
                {
                    found.Add((file.RelativePath, start, run.Count, string.Join('\n', run)));
                }

                run.Clear();
            }
        }

        var ordered = found.OrderByDescending(f => f.Length).ToList();

        if (ordered.Count > MaxReported)
        {
            limitations.Add(
                $"{ordered.Count - MaxReported:N0} further block"
                + $"{(ordered.Count - MaxReported == 1 ? "" : "s")} of commented-out code "
                + "were found and not listed individually.");
        }

        foreach (var block in ordered.Take(MaxReported))
        {
            yield return new Finding
            {
                RuleId = "VC-DUP-003",
                Title = $"{block.Length} lines of commented-out code",
                Severity = Severity.Info,
                UserSeverity = Severity.Info,
                Category = FindingCategory.Maintainability,
                Source = FindingSource.Rule,
                Description =
                    $"{block.Length} consecutive commented lines here parse as code rather than "
                    + "as prose. Commented-out code is dead weight that still has to be read, "
                    + "and it goes stale silently because nothing compiles it.",
                UserDescription =
                    "The application carries code that has been switched off by commenting it "
                    + "out. It does not run, and it does not affect you.",
                Evidence = Excerpt(block.Text),
                Remediation =
                    "Delete it. Version control already remembers it, which is what made it safe "
                    + "to remove in the first place.",
                FilePath = block.Path,
                Line = block.Line,
            };
        }
    }

    // ---- Shared helpers ----------------------------------------------------

    /// <summary>Only real source. Config and markup repeat legitimately by their nature.</summary>
    private static bool IsCode(SourceLanguage language) => language is SourceLanguage.CSharp
        or SourceLanguage.JavaScript or SourceLanguage.TypeScript or SourceLanguage.Python
        or SourceLanguage.Java;

    /// <summary>
    /// Lines that carry logic. Imports, blank lines, lone braces and comments are excluded,
    /// because every file in a project shares those and matching on them would report the
    /// language's own boilerplate as duplicated work.
    /// </summary>
    private static List<string> Significant(string content) =>
        [.. SignificantWithNumbers(content).Select(l => l.Text)];

    private static List<(int Number, string Text)> SignificantWithNumbers(string content)
    {
        var result = new List<(int, string)>();
        var lines = content.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim().TrimEnd('\r').Trim();

            if (trimmed.Length == 0
                || trimmed is "{" or "}" or "};" or ")" or ");" or "]" or "];" or "else"
                || trimmed.StartsWith("//", StringComparison.Ordinal)
                || trimmed.StartsWith('#')
                || trimmed.StartsWith("*", StringComparison.Ordinal)
                || trimmed.StartsWith("/*", StringComparison.Ordinal)
                || trimmed.StartsWith("using ", StringComparison.Ordinal)
                || trimmed.StartsWith("import ", StringComparison.Ordinal)
                || trimmed.StartsWith("from ", StringComparison.Ordinal)
                || trimmed.StartsWith("export ", StringComparison.Ordinal)
                || trimmed.StartsWith("package ", StringComparison.Ordinal)
                || trimmed.StartsWith("namespace ", StringComparison.Ordinal))
            {
                continue;
            }

            result.Add((i + 1, trimmed));
        }

        return result;
    }

    /// <summary>The comment body, or null when the line is not a single-line comment.</summary>
    private static string? StripComment(string line)
    {
        var trimmed = line.Trim().TrimEnd('\r').Trim();

        return trimmed.StartsWith("//", StringComparison.Ordinal) ? trimmed[2..].Trim()
            : trimmed.StartsWith("# ", StringComparison.Ordinal) ? trimmed[1..].Trim()
            : null;
    }

    /// <summary>
    /// Whether commented text is code rather than prose.
    /// </summary>
    /// <remarks>
    /// Deliberately strict. A comment explaining why something is done is the most valuable
    /// thing in a file, and a check that reported explanatory comments as dead weight would be
    /// actively harmful advice. So this requires punctuation that prose does not use: a
    /// statement terminator, an assignment, or a call.
    /// </remarks>
    private static bool LooksLikeCode(string text)
    {
        if (text.Length < 4 || text.EndsWith('.') || text.EndsWith('?') || text.EndsWith('!'))
        {
            return false;
        }

        return text.EndsWith(';') || text.EndsWith('{') || text.EndsWith('}') || text.EndsWith(',')
               || (text.Contains('(') && text.Contains(')'))
               || (text.Contains('=') && !text.Contains("==", StringComparison.Ordinal));
    }

    /// <summary>Keeps evidence to something a reader will actually look at.</summary>
    private static string Excerpt(string text)
    {
        var lines = text.Split('\n');

        return lines.Length <= 6
            ? text
            : string.Join('\n', lines.Take(6)) + $"\n... ({lines.Length - 6} more lines)";
    }

    private static string Hash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
