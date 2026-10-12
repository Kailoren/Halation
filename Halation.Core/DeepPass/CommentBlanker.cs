namespace Halation.Core.DeepPass;

/// <summary>
/// A copy of a source file with its comments blanked out, and its code and strings left where
/// they were.
/// </summary>
/// <remarks>
/// <para>
/// Written for triage, which picks files for the deep pass by looking for the names of calls
/// that bring data in. A comment that names one of those calls is not a call. On a World of
/// Warcraft addon four of the six files picked were picked for their comments, one of them
/// explaining that a multiplication is checked "so an edited setting cannot round an unsafe
/// value", and the pass spent its budget reading prose.
/// </para>
/// <para>
/// Strings are kept, quotes and all, and keeping them is most of the work here. A URL is two
/// slashes inside quotation marks, and reading those as a comment would blank every call after
/// it on the same line, which in a minified bundle is every call in the file. An event name a
/// Lua addon registers for is a string too, and it is what the Lua list looks for. Strings
/// with holes in them, JavaScript's template literals and C#'s interpolated strings, are
/// followed into the holes and back out, because a hole is code and can hold strings of its
/// own. JavaScript's regular expression literals are strings for this purpose as well, since
/// the quote in <c>/"/g</c> opens nothing.
/// </para>
/// <para>
/// Where the scan cannot be sure, it leaves the text alone. Blanking code drops a file the deep
/// pass should have read, while leaving a comment in only keeps a file that was being read
/// before this existed. So a block comment that never ends is not taken for a comment, and a
/// quote that has not closed by the end of its line closes there, which stops one apostrophe in
/// the wrong place from turning the rest of the file inside out. Other languages' strings can
/// hold quoted strings too, Kotlin's <c>"${f("x")}"</c> or a shell's <c>"$(cmd "x")"</c>, and
/// those are not followed in; the worst that does is blank the rest of one line.
/// </para>
/// <para>
/// One pass from the start of the file to the end that never steps back, so the cost follows
/// the length of the file whatever is in it. The searches ahead for the end of a block comment
/// remember when they found nothing, because nothing further on will find one either; without
/// that, a file of unclosed openers would be searched to the end once for each of them.
/// </para>
/// <para>
/// Checked against Roslyn, acorn and Python's own tokenizer on about 27,000 real files,
/// minified bundles among them, it blanked nothing that any of them reads as code. It leaves
/// a few comments in: a <c>#!</c> line, and a Python <c>#</c> with no space before it.
/// </para>
/// </remarks>
internal static class CommentBlanker
{
    /// <summary>
    /// The file's text with every comment character replaced by a space, or the text itself
    /// when there were no comments or the language is not one this knows.
    /// </summary>
    /// <remarks>
    /// Line breaks inside a comment are kept, so the copy has the same lines as the file.
    /// </remarks>
    public static string Blank(string content, string path)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(path);

        return SyntaxOf(path) is { } syntax ? new Scan(content, syntax).Run() : content;
    }

    /// <summary>The parts of a language's syntax that say where its comments and strings are.</summary>
    private sealed record Syntax
    {
        /// <summary><c>//</c> to the end of the line.</summary>
        public bool DoubleSlash { get; init; }

        /// <summary><c>/* */</c>.</summary>
        public bool SlashStar { get; init; }

        /// <summary><c>#</c> to the end of the line, where it starts the line or follows a space.</summary>
        /// <remarks>
        /// The space is what tells <c>$#</c>, <c>${#name}</c> and the fragment in a URL in a YAML
        /// value from a comment. Python would accept a comment straight after code, and missing
        /// that only leaves a comment in.
        /// </remarks>
        public bool Hash { get; init; }

        /// <summary><c>--</c> to the end of the line.</summary>
        public bool Dashes { get; init; }

        /// <summary>
        /// Lua's long brackets: <c>--[[ ]]</c> and <c>--[==[ ]==]</c> are comments, and the same
        /// brackets without the dashes are strings. Each closes only on the same number of
        /// equals signs, so <c>]]</c> inside a level-two comment is part of it.
        /// </summary>
        public bool LongBrackets { get; init; }

        /// <summary>PowerShell's <c>&lt;# #&gt;</c>.</summary>
        public bool AngleHash { get; init; }

        /// <summary>
        /// <c>&lt;!-- --&gt;</c>, and no strings at all. A quote in markup is far more often an
        /// apostrophe in running text than the start of anything.
        /// </summary>
        public bool Markup { get; init; }

        /// <summary><c>"""</c> and <c>'''</c>, which run across lines.</summary>
        public bool TripleQuotes { get; init; }

        /// <summary>
        /// C#'s verbatim and interpolated strings: <c>@"..."</c>, which runs across lines and
        /// escapes a quote by doubling it, and <c>$"..."</c> in each of its forms.
        /// </summary>
        public bool CSharpStrings { get; init; }

        /// <summary>JavaScript's template literals, whose <c>${ }</c> holes are code.</summary>
        public bool Templates { get; init; }

        /// <summary>Go's raw strings, which run to the next backtick with no escapes.</summary>
        public bool RawBackticks { get; init; }

        /// <summary>JavaScript's regular expression literals, told from division by what comes before.</summary>
        public bool RegexLiterals { get; init; }

        /// <summary>The character that escapes the next one, inside strings and out.</summary>
        public char Escape { get; init; } = '\\';
    }

    private static readonly Syntax CLike = new() { DoubleSlash = true, SlashStar = true };

    private static readonly Syntax CSharp = CLike with { TripleQuotes = true, CSharpStrings = true };

    /// <summary>The C-like languages with a triple-quoted string: Java and Kotlin text blocks and the like.</summary>
    private static readonly Syntax TextBlocks = CLike with { TripleQuotes = true };

    private static readonly Syntax JavaScript = CLike with { Templates = true, RegexLiterals = true };

    private static readonly Syntax Go = CLike with { RawBackticks = true };

    private static readonly Syntax HashLine = new() { Hash = true };

    private static readonly Syntax Python = HashLine with { TripleQuotes = true };

    private static readonly Syntax PowerShell = HashLine with { AngleHash = true, Escape = '`' };

    private static readonly Syntax Lua = new() { Dashes = true, LongBrackets = true };

    private static readonly Syntax Sql = new() { Dashes = true, SlashStar = true };

    private static readonly Syntax MarkupOnly = new() { Markup = true };

    /// <summary>The syntax a file is written in, by its extension, or null for one this does not know.</summary>
    /// <remarks>
    /// PHP is read as C-like and its <c>#</c> comments are left in, since <c>#[</c> opens an
    /// attribute there. JSON is C-like because the configuration files that allow comments in it
    /// use the C ones, and plain JSON has nothing outside its strings that could be mistaken for
    /// one.
    /// </remarks>
    private static Syntax? SyntaxOf(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".js" or ".jsx" or ".mjs" or ".cjs" or ".ts" or ".tsx" or ".mts" or ".cts" => JavaScript,
        ".cs" => CSharp,
        ".java" or ".kt" or ".scala" or ".groovy" or ".swift" or ".dart" => TextBlocks,
        ".go" => Go,
        ".c" or ".h" or ".cpp" or ".cc" or ".hpp" or ".cxx" or ".m" or ".mm" or ".rs" or ".zig"
            or ".php" or ".fs" or ".fsx" or ".json" => CLike,
        ".py" or ".pyw" => Python,
        ".ps1" => PowerShell,
        ".sh" or ".bash" or ".rb" or ".pl" or ".r" or ".ex" or ".exs" or ".jl"
            or ".yml" or ".yaml" or ".toml" or ".ini" => HashLine,
        ".lua" => Lua,
        ".sql" => Sql,
        ".html" or ".htm" or ".xml" or ".config" or ".xaml" or ".vue" or ".svelte" or ".razor"
            or ".cshtml" or ".astro" or ".erb" or ".ejs" or ".hbs" or ".twig" => MarkupOnly,
        _ => null,
    };

    /// <summary>
    /// Deepest Lua long bracket taken as one. Real code stops at two or three equals signs; a
    /// limit keeps the number of different closers searched for, and so the cost, bounded.
    /// </summary>
    private const int MaxLongBracketLevel = 16;

    private static readonly string[] LongClosers =
    [
        .. Enumerable.Range(0, MaxLongBracketLevel + 1).Select(level => "]" + new string('=', level) + "]"),
    ];

    /// <summary>
    /// Longest run of quotes taken as one opener. C# allows any number from three, and a closer
    /// is searched for at each length used, so the lengths are capped the same way.
    /// </summary>
    private const int MaxQuoteRun = 8;

    /// <summary>A string with holes in it.</summary>
    private enum Holed
    {
        /// <summary>JavaScript's <c>`...${ }...`</c>.</summary>
        Template,

        /// <summary>C#'s <c>$"...{ }..."</c>, which ends at the end of its line.</summary>
        Interpolated,

        /// <summary>C#'s <c>$@"...{ }..."</c>, where a doubled quote is a quote.</summary>
        VerbatimInterpolated,

        /// <summary>C#'s <c>$"""...{ }..."""</c>, opened and closed by the same number of quotes.</summary>
        RawInterpolated,
    }

    /// <summary>A hole the scan is in, and the string to go back to when it closes.</summary>
    /// <param name="Kind">What sort of string the hole is in.</param>
    /// <param name="Quotes">For a raw string, how many quotes close it.</param>
    /// <param name="Dollars">For a raw string, how many braces it takes to open a hole.</param>
    private sealed record Hole(Holed Kind, int Quotes = 0, int Dollars = 1)
    {
        /// <summary>How many of the hole's own braces are open, so its closing brace can be told from theirs.</summary>
        public int Depth { get; set; }
    }

    /// <summary>One file's scan. Everything it moves through is code until it says otherwise.</summary>
    private sealed class Scan(string text, Syntax syntax)
    {
        /// <summary>The copy being blanked, made the first time a comment turns up.</summary>
        private char[]? _blanked;

        /// <summary>For each closer, where a search for it last found nothing.</summary>
        private readonly Dictionary<string, int> _noCloserFrom = new(StringComparer.Ordinal);

        /// <summary>The holes the scan is inside, innermost on top.</summary>
        private Stack<Hole>? _holes;

        /// <summary>The last character of code that was not white space, and where it was.</summary>
        /// <remarks>
        /// What tells a regular expression from a division: after <c>(</c> or <c>=</c> a slash
        /// starts a pattern, and after a name or a closing bracket it divides.
        /// </remarks>
        private char _prev;

        private int _prevAt = -1;

        public string Run()
        {
            var i = 0;

            while (i < text.Length)
            {
                i = Next(i);
            }

            return _blanked is null ? text : new string(_blanked);
        }

        /// <summary>Reads whatever starts at <paramref name="i"/> and returns where the next thing starts.</summary>
        private int Next(int i)
        {
            var c = text[i];

            if (char.IsWhiteSpace(c))
            {
                return i + 1;
            }

            if (CommentEnd(i) is { } end)
            {
                Blank(i, end);
                return end;
            }

            if (syntax.Markup)
            {
                return i + 1;
            }

            if (c == syntax.Escape)
            {
                Code(i);
                return i + 2;
            }

            if (c is '"' or '\'')
            {
                return Literal(Quoted(i));
            }

            if (syntax.CSharpStrings && c is '$' or '@' && CSharpString(i) is { } after)
            {
                return after;
            }

            if (c == '`' && syntax.Templates)
            {
                return InString(i + 1, new Hole(Holed.Template));
            }

            if (c == '`' && syntax.RawBackticks)
            {
                var close = text.IndexOf('`', i + 1);

                return Literal(close < 0 ? text.Length : close + 1);
            }

            if (c == '[' && syntax.LongBrackets && LongBracket(i) is { } level)
            {
                // A long string, so a "--" inside it stays. One that never closes runs to the
                // end of the file: Lua would refuse it, and treating the rest as code could only
                // blank more.
                return Literal(Closer(i + level + 2, LongClosers[level]) ?? text.Length);
            }

            if (c == '/' && syntax.RegexLiterals && !At(i + 1, '*') && PatternCanStart())
            {
                return Literal(Pattern(i));
            }

            if (_holes is { Count: > 0 } && c is '{' or '}')
            {
                var hole = _holes.Peek();

                if (c == '}' && hole.Depth == 0)
                {
                    _holes.Pop();
                    return InString(i + 1, hole);
                }

                hole.Depth += c == '{' ? 1 : -1;
            }

            Code(i);
            return i + 1;
        }

        /// <summary>Where a comment starting at <paramref name="i"/> ends, or null when none starts there.</summary>
        private int? CommentEnd(int i)
        {
            var c = text[i];

            if (c == '/' && syntax.DoubleSlash && At(i + 1, '/'))
            {
                return LineEnd(i);
            }

            if (c == '/' && syntax.SlashStar && At(i + 1, '*'))
            {
                return Closer(i + 2, "*/");
            }

            if (c == '-' && syntax.Dashes && At(i + 1, '-'))
            {
                if (syntax.LongBrackets
                    && LongBracket(i + 2) is { } level
                    && Closer(i + level + 4, LongClosers[level]) is { } end)
                {
                    return end;
                }

                // Including a long bracket that never closes, which Lua would refuse. As a line
                // comment it blanks less than the alternative.
                return LineEnd(i);
            }

            if (c == '#' && syntax.Hash && (i == 0 || char.IsWhiteSpace(text[i - 1])))
            {
                return LineEnd(i);
            }

            if (c == '<' && syntax.AngleHash && At(i + 1, '#'))
            {
                return Closer(i + 2, "#>");
            }

            if (c == '<' && syntax.Markup && text.AsSpan(i).StartsWith("<!--", StringComparison.Ordinal))
            {
                return Closer(i + 4, "-->");
            }

            return null;
        }

        /// <summary>The end of a <c>"</c> or <c>'</c> string, triple-quoted or not.</summary>
        private int Quoted(int i)
        {
            var quote = text[i];

            if (syntax.TripleQuotes && At(i + 1, quote) && At(i + 2, quote))
            {
                return TripleQuoted(i);
            }

            var j = i + 1;

            while (j < text.Length)
            {
                var c = text[j];

                if (c == quote)
                {
                    return j + 1;
                }

                if (c == '\n')
                {
                    return j;
                }

                j += c == syntax.Escape ? 2 : 1;
            }

            return text.Length;
        }

        /// <summary>The end of a triple-quoted string opening at <paramref name="i"/>.</summary>
        /// <remarks>
        /// Two rules. A C# raw string opens with three quotes or more, closes on as many, and
        /// has no escapes. Everywhere else the opener is exactly three, and a backslash keeps
        /// the quote after it from closing the string, which is how the pattern IDLE uses to
        /// find Python strings, <c>r"""...\"""..."""</c>, holds three quotes in a row.
        /// </remarks>
        private int TripleQuoted(int i)
        {
            var quote = text[i];

            if (syntax.CSharpStrings)
            {
                var run = RunOf(i, quote);

                return Closer(i + run, new string(quote, Math.Min(run, MaxQuoteRun))) ?? text.Length;
            }

            var j = i + 3;

            while (j < text.Length)
            {
                var c = text[j];

                if (c == syntax.Escape)
                {
                    j += 2;
                    continue;
                }

                if (c == quote)
                {
                    var run = RunOf(j, quote);

                    if (run >= 3)
                    {
                        return j + 3;
                    }

                    j += run;
                    continue;
                }

                j++;
            }

            return text.Length;
        }

        /// <summary>
        /// Reads a C# string that starts with <c>@</c> or <c>$</c> at <paramref name="i"/>, or
        /// returns null when what starts there is not one.
        /// </summary>
        private int? CSharpString(int i)
        {
            var dollars = RunOf(i, '$');
            var at = i + dollars;
            var verbatim = At(at, '@');

            // Both orders of the two prefixes are allowed: $@"..." and @$"...".
            if (dollars == 0 && verbatim)
            {
                dollars = RunOf(at + 1, '$');
                at += 1 + dollars;
            }
            else if (verbatim)
            {
                at++;
            }

            if (!At(at, '"'))
            {
                return null;
            }

            if (dollars == 0)
            {
                return Literal(Verbatim(at + 1));
            }

            if (verbatim)
            {
                return InString(at + 1, new Hole(Holed.VerbatimInterpolated));
            }

            var quotes = RunOf(at, '"');

            return quotes >= 3
                ? InString(at + quotes, new Hole(Holed.RawInterpolated, quotes, dollars))
                : InString(at + 1, new Hole(Holed.Interpolated));
        }

        /// <summary>The end of a C# verbatim string whose text starts at <paramref name="i"/>.</summary>
        private int Verbatim(int i)
        {
            while (i < text.Length)
            {
                if (text[i] == '"')
                {
                    if (!At(i + 1, '"'))
                    {
                        return i + 1;
                    }

                    i++;
                }

                i++;
            }

            return text.Length;
        }

        /// <summary>
        /// Reads the text of a string with holes from <paramref name="i"/>, to its end or to its
        /// next hole, which hands back to the code it holds.
        /// </summary>
        /// <remarks>
        /// Followed into the holes rather than paired off quote by quote, because a hole can
        /// hold a string of its own, <c>`${a ? `https://x` : ""}`</c> in minified JavaScript or
        /// <c>$"{Get("https://x")}"</c> in C#, and pairing the quotes would read the inner URL
        /// as code and blank the rest of its line.
        /// </remarks>
        private int InString(int i, Hole hole)
        {
            while (i < text.Length)
            {
                var c = text[i];

                switch (hole.Kind)
                {
                    case Holed.Template:
                        if (c == '\\')
                        {
                            i += 2;
                            continue;
                        }

                        if (c == '`')
                        {
                            return Literal(i + 1);
                        }

                        if (c == '$' && At(i + 1, '{'))
                        {
                            return Open(hole, i + 1);
                        }

                        i++;
                        continue;

                    case Holed.Interpolated when c == '\\':
                        i += 2;
                        continue;

                    case Holed.Interpolated when c == '"':
                        return Literal(i + 1);

                    case Holed.Interpolated when c == '\n':
                        return i;

                    case Holed.VerbatimInterpolated when c == '"':
                        if (!At(i + 1, '"'))
                        {
                            return Literal(i + 1);
                        }

                        i += 2;
                        continue;

                    case Holed.RawInterpolated when c == '"':
                        var quotes = RunOf(i, '"');

                        if (quotes >= hole.Quotes)
                        {
                            return Literal(i + hole.Quotes);
                        }

                        i += quotes;
                        continue;
                }

                if (c == '{')
                {
                    // A doubled brace is a brace in the text, except in a raw string, where it
                    // takes as many braces as the string has dollar signs to open a hole.
                    var braces = RunOf(i, '{');

                    if (hole.Kind == Holed.RawInterpolated ? braces >= hole.Dollars : braces % 2 == 1)
                    {
                        return Open(hole, i + braces - 1);
                    }

                    i += braces;
                    continue;
                }

                i++;
            }

            return text.Length;
        }

        /// <summary>Steps into a hole whose opening brace is at <paramref name="brace"/>.</summary>
        private int Open(Hole hole, int brace)
        {
            (_holes ??= new()).Push(hole with { Depth = 0 });
            Code(brace);
            return brace + 1;
        }

        /// <summary>
        /// The end of a regular expression literal opening at <paramref name="i"/>.
        /// </summary>
        /// <remarks>
        /// A slash inside a character class does not close it, which is what <c>/[/*]/</c>
        /// needs. One that has not closed by the end of the line was not a pattern after all;
        /// the rest of the line is passed over rather than read again from the slash, which on
        /// a one-line bundle would be the rest of the file each time.
        /// </remarks>
        private int Pattern(int i)
        {
            var j = i + 1;
            var inClass = false;

            while (j < text.Length)
            {
                var c = text[j];

                if (c == '\\')
                {
                    j += 2;
                    continue;
                }

                if (c is '\n' or '\r')
                {
                    return j;
                }

                if (inClass)
                {
                    inClass = c != ']';
                }
                else if (c == '[')
                {
                    inClass = true;
                }
                else if (c == '/')
                {
                    return j + 1;
                }

                j++;
            }

            return text.Length;
        }

        /// <summary>Whether a slash here would start a regular expression rather than divide.</summary>
        /// <remarks>
        /// The usual rule from the language's own grammar, short of parsing it: a pattern follows
        /// an operator, an opening bracket, the start of the file, or a keyword that takes a
        /// value, and anything else that can end a value means division. The keyword is looked
        /// for no further back than the longest keyword, so this costs the same at every slash.
        /// </remarks>
        private bool PatternCanStart()
        {
            if (_prevAt < 0 || "(,=:[!&|?{};+-*%<>~^".Contains(_prev, StringComparison.Ordinal))
            {
                return true;
            }

            if (!IsIdentifier(_prev))
            {
                return false;
            }

            const int longest = 10;
            var start = _prevAt;

            while (start > 0 && _prevAt - start < longest && IsIdentifier(text[start - 1]))
            {
                start--;
            }

            if (start > 0 && IsIdentifier(text[start - 1]))
            {
                return false;
            }

            return text.AsSpan(start, _prevAt - start + 1)
                is "return" or "typeof" or "instanceof" or "in" or "of" or "new" or "delete"
                or "void" or "throw" or "case" or "do" or "else" or "yield" or "await";
        }

        private static bool IsIdentifier(char c) => char.IsLetterOrDigit(c) || c is '_' or '$';

        /// <summary>
        /// The end of a closer searched for from <paramref name="from"/>, or null when there is
        /// none.
        /// </summary>
        /// <remarks>
        /// The scan only moves forward, so a search that found nothing from one place will find
        /// nothing from any later one, and is not run again.
        /// </remarks>
        private int? Closer(int from, string closer)
        {
            if (from > text.Length
                || (_noCloserFrom.TryGetValue(closer, out var none) && from >= none))
            {
                return null;
            }

            var at = text.IndexOf(closer, from, StringComparison.Ordinal);

            if (at < 0)
            {
                _noCloserFrom[closer] = from;
                return null;
            }

            return at + closer.Length;
        }

        /// <summary>The level of a Lua long bracket opening at <paramref name="i"/>, or null when none does.</summary>
        private int? LongBracket(int i)
        {
            if (!At(i, '['))
            {
                return null;
            }

            var level = 0;

            while (level <= MaxLongBracketLevel && At(i + 1 + level, '='))
            {
                level++;
            }

            return level <= MaxLongBracketLevel && At(i + 1 + level, '[') ? level : null;
        }

        /// <summary>How many times <paramref name="c"/> repeats from <paramref name="i"/>.</summary>
        private int RunOf(int i, char c)
        {
            var j = i;

            while (j < text.Length && text[j] == c)
            {
                j++;
            }

            return j - i;
        }

        private int LineEnd(int i)
        {
            var end = text.IndexOf('\n', i);

            return end < 0 ? text.Length : end;
        }

        private bool At(int i, char c) => i < text.Length && text[i] == c;

        private void Code(int i)
        {
            _prev = text[i];
            _prevAt = i;
        }

        /// <summary>Records a string or pattern ending at <paramref name="end"/> as a value, after which a slash divides.</summary>
        private int Literal(int end)
        {
            _prev = '"';
            _prevAt = end - 1;
            return end;
        }

        private void Blank(int from, int to)
        {
            _blanked ??= text.ToCharArray();

            for (var k = from; k < to; k++)
            {
                if (_blanked[k] is not ('\n' or '\r'))
                {
                    _blanked[k] = ' ';
                }
            }
        }
    }
}
