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

/// <summary>Which files were chosen, and how many were in the running.</summary>
public sealed record TriageResult
{
    public IReadOnlyList<TriagedFile> Selected { get; init; } = [];

    /// <summary>How many files qualified, before the ceiling on how many are sent.</summary>
    public int Qualified { get; init; }

    /// <summary>True when the ceiling, rather than the code, decided where to stop.</summary>
    public bool HitCeiling => Qualified > Selected.Count;

    /// <summary>Recovered files taken for tests or examples, which only a rule match brings in.</summary>
    public int TestFiles { get; init; }

    /// <summary>
    /// Languages of the code outside the tests that the surface patterns were not written for,
    /// named for the report, the language with the most files first.
    /// </summary>
    public IReadOnlyList<string> LanguagesWithoutPatterns { get; init; } = [];
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
    /// requests on its own. A pass that uses every request sends twice what forty truncated
    /// files could, so the worst case is double the old one; <see cref="CeilingCostUsd"/> is
    /// what the interface quotes for it. A pass that reaches the ceiling says so and reports the
    /// coverage it actually achieved rather than reading on quietly.
    /// </remarks>
    public const int DefaultMaxRequests = 80;

    /// <summary>
    /// Roughly what a pass that uses every request costs on an Anthropic API key, in US dollars.
    /// </summary>
    /// <remarks>
    /// Worked out on paper, with no scan measured at the ceiling. <see cref="CeilingChars"/>
    /// characters is somewhere between 1.2 and 1.5 million input tokens at Claude Opus 5.5's
    /// US$4 a million, plus the findings that come back at US$20 a million. It was ten under
    /// Claude Opus 5, whose US$5 and US$25 were both a quarter higher, so the same pass costs a
    /// fifth less. A test reprices it from <see cref="TokenUsage.EstimatedCost"/>, so changing the
    /// rates fails until this is worked out again. The app's cost copy interpolates it;
    /// docs/setup.html states it in prose and has to be changed by hand.
    /// </remarks>
    public const int CeilingCostUsd = 8;

    /// <summary>
    /// What a pass that uses every request sends, which is the size <see cref="CeilingCostUsd"/>
    /// was worked out for.
    /// </summary>
    /// <remarks>
    /// A test checks this against the two limits, so moving either one fails until the figure
    /// is worked out again. The quoted figure stayed at five dollars once already after the
    /// request ceiling doubled what a scan could send.
    /// </remarks>
    public const long CeilingChars = 4_800_000;

    /// <summary>
    /// Calls that put data the application does not control into its hands, or hand its data
    /// to something outside it. A file making none of these calls gives the model no untrusted
    /// input to follow, so it is not worth paying for.
    /// </summary>
    /// <remarks>
    /// Written as these calls are spelled in C#, JavaScript and TypeScript. It applies to every
    /// file, and a few of the names, <c>eval(</c> and <c>Socket</c> among them, mean the same in
    /// other languages, but nobody has gone through Python or Go for the ways they take data in.
    /// The report names the languages this leaves short. Matched against the file with its
    /// comments blanked, see <see cref="CommentBlanker"/>.
    /// </remarks>
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
    /// The same for Lua, applied to <c>.lua</c> files on top of the list above.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Most of the Lua that gets scanned is World of Warcraft addons, and an addon takes data in
    /// from outside in a few recognisable ways: chat and addon-channel events carrying text that
    /// other players wrote, a string pasted into an edit box, and an import string decoded and
    /// decompressed back into a table. Running a string as code is the call that turns any of
    /// those into something worse. The standard library's file and shell calls are here for Lua
    /// that runs outside the game. <c>RegisterComm</c> and <c>SendCommMessage</c> are AceComm's,
    /// which most addons use in place of the raw addon-message calls.
    /// </para>
    /// <para>
    /// An edit box is known by what makes one: being created as one, the handlers that fire as
    /// somebody types into it or leaves it, and the two stock templates that build one. Reading
    /// its text is not enough on its own, because <c>:GetText()</c> reads a label or a button
    /// just the same, and on an addon whose interface sets text everywhere that picked files
    /// with no box in them at all. The handler and template names are matched inside strings,
    /// which is where <c>SetScript</c> and <c>CreateFrame</c> take them.
    /// </para>
    /// <para>
    /// Case-sensitive, because Lua is: <c>Load(</c> is somebody's own function. A method call
    /// named <c>load</c> is left out for the same reason.
    /// </para>
    /// </remarks>
    private static readonly Regex LuaSurface = PatternRule.Compile(
        """
        \b(?:loadstring|loadfile|dofile|RunScript)\b
        |(?<![.:\w])load\s*\(
        |\b(?:BN_)?CHAT_MSG_[A-Z_]+
        |\b(?:SendAddonMessage(?:Logged)?|RegisterAddonMessagePrefix|RegisterComm|SendCommMessage)\b
        |\bCreateFrame\s*\(\s*["']EditBox["']
        |\b(?:OnEnterPressed|OnTextChanged|OnEditFocusLost|InputBoxTemplate|SearchBoxTemplate)\b
        |\bio\.(?:open|read|lines|popen)\b
        |\bos\.execute\b
        |\b(?:DecodeForPrint|DecodeForWoWAddonChannel|DecodeForWoWChatChannel|DecompressDeflate|DecompressZlib)\b
        """,
        RegexOptions.IgnorePatternWhitespace);

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

        // Test and example files come in only when a rule matched in them. Scanning a whole
        // repository sent 38 test specs among its 40 files: a spec stubs the network, opens
        // fixtures and calls the code under test by name, so it matches the surface list and
        // the caller hop more readily than the code it tests does, and it is the code least
        // worth paying to read, since it does not ship.
        var shipped = files.Where(f => !Heuristics.IsTestOrExampleFile(f.RelativePath)).ToList();

        // Each file with its place in the order: flagged, caller, surface, flagged test.
        var selected = new Dictionary<string, (TriagedFile File, int Rank)>(StringComparer.OrdinalIgnoreCase);

        // 1. Files the deterministic pass already flagged. The model's job on these is to
        //    judge whether the finding is real and how far it reaches, not to rediscover it.
        foreach (var file in files.Where(f => byPath.ContainsKey(f.RelativePath)))
        {
            var test = Heuristics.IsTestOrExampleFile(file.RelativePath);

            selected[file.RelativePath] = (new TriagedFile
            {
                File = file,
                Reason = test
                    ? "a deterministic rule matched here, in a test or example file"
                    : "a deterministic rule matched here",
                KnownFindings = byPath[file.RelativePath],
            }, test ? 3 : 0);
        }

        // 2. Callers of anything flagged. This is the hop that turns "unbounded allocation"
        //    into "unbounded allocation reachable from a remote response". A flagged test is
        //    not followed: shipped code does not reach into a test, and a test helper's name
        //    matched against the application's own imports finds files that do not call it.
        var flagged = selected.Where(s => s.Value.Rank == 0).Select(s => s.Key).ToList();

        foreach (var file in CallersOf(shipped, flagged))
        {
            if (!selected.ContainsKey(file.RelativePath))
            {
                selected[file.RelativePath] = (new TriagedFile
                {
                    File = file,
                    Reason = "calls into a file that a rule matched",
                }, 1);
            }
        }

        // 3. Everything else that handles untrusted input, whether or not a rule fired.
        foreach (var file in shipped)
        {
            if (selected.ContainsKey(file.RelativePath) || !HandlesUntrustedInput(file))
            {
                continue;
            }

            selected[file.RelativePath] = (new TriagedFile
            {
                File = file,
                Reason = "handles input the application does not control",
            }, 2);
        }

        // Flagged files first, then their callers, then the wider surface: if the budget runs
        // out, it should run out on the least likely candidates. A flagged test goes after all
        // of them, however many findings it has, so it only gets a slot the shipped code left.
        var ranked = selected.Values
            .OrderBy(s => s.Rank)
            .ThenByDescending(s => s.File.KnownFindings.Count)
            .Select(s => s.File)
            .ToList();

        return new TriageResult
        {
            Selected = [.. ranked.Take(maxFiles)],
            Qualified = ranked.Count,
            TestFiles = files.Count - shipped.Count,
            LanguagesWithoutPatterns = LanguagesWithoutPatterns(shipped),
        };
    }

    /// <summary>
    /// The languages of the given files that the surface patterns were not written for, the
    /// one with the most files first.
    /// </summary>
    private static IReadOnlyList<string> LanguagesWithoutPatterns(IEnumerable<RecoveredFile> files) =>
    [
        .. files
            .Select(UnpatternedLanguageOf)
            .OfType<string>()
            .GroupBy(name => name, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => g.Key),
    ];

    /// <summary>
    /// The name of a file's language when it is program code that neither surface list was
    /// written for, or null.
    /// </summary>
    /// <remarks>
    /// Left out on purpose: C#, JavaScript, TypeScript and Lua, which have patterns; text that
    /// is not a program, such as SQL, GraphQL, protocol definitions, markup and configuration;
    /// and templates, whose code is in a language already counted. A C header is left out too,
    /// because on its own it cannot say whether it belongs to C or C++, and the source files
    /// beside it can.
    /// </remarks>
    private static string? UnpatternedLanguageOf(RecoveredFile file)
    {
        var extension = Path.GetExtension(file.RelativePath).ToLowerInvariant();

        return file.Language switch
        {
            SourceLanguage.Python => "Python",
            SourceLanguage.Java => extension == ".kt" ? "Kotlin" : "Java",
            SourceLanguage.Shell => extension switch
            {
                ".ps1" => "PowerShell",
                ".bat" or ".cmd" => "Windows batch",
                _ => "shell script",
            },
            SourceLanguage.Other => extension switch
            {
                ".go" => "Go",
                ".rs" => "Rust",
                ".rb" => "Ruby",
                ".php" => "PHP",
                ".swift" => "Swift",
                ".dart" => "Dart",
                ".scala" => "Scala",
                ".ex" or ".exs" => "Elixir",
                ".pl" => "Perl",
                ".r" => "R",
                ".jl" => "Julia",
                ".zig" => "Zig",
                ".groovy" => "Groovy",
                ".m" or ".mm" => "Objective-C",
                ".c" => "C",
                ".cpp" or ".cc" or ".hpp" or ".cxx" => "C++",
                ".vb" => "Visual Basic",
                ".fs" or ".fsx" => "F#",
                ".clj" or ".cljs" => "Clojure",
                ".elm" => "Elm",
                ".hs" => "Haskell",
                _ => null,
            },
            _ => null,
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

    /// <summary>Whether a file makes any of the surface calls, outside its comments.</summary>
    private static bool HandlesUntrustedInput(RecoveredFile file)
    {
        var code = CommentBlanker.Blank(file.Content, file.RelativePath);

        return UntrustedSurface.IsMatch(code)
            || (file.RelativePath.EndsWith(".lua", StringComparison.OrdinalIgnoreCase)
                && LuaSurface.IsMatch(code));
    }
}
