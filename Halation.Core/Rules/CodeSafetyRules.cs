using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.Rules;

/// <summary>
/// Injection sinks, unsafe deserialisation, and weak cryptography.
/// </summary>
/// <remarks>
/// These rules look for a dangerous operation fed by interpolated or concatenated input,
/// rather than for the operation alone. Flagging every call to a query method would bury the
/// real findings; the composition is what makes it exploitable.
/// </remarks>
public static class CodeSafetyRules
{
    /// <summary>
    /// A bare <c>Name = 1234,</c> line, which is an enum member rather than a use of
    /// whatever the name refers to. Declared before the rules that reference it so static
    /// initialisation sees it set.
    /// </summary>
    private static readonly Regex EnumMemberDeclaration = PatternRule.Compile(
        """^\s*\w+\s*=\s*(?:0x[0-9a-fA-F]+|\d+)\s*,?\s*$""");

    /// <summary>
    /// Whether a match is a lowercase word inside a sentence rather than an algorithm name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The test is the string the match sits in, not the characters beside it. An algorithm
    /// name is a bare token however it is written: <c>"des"</c>, <c>"des-ede3-cbc"</c>,
    /// <c>"DES/ECB/PKCS5Padding"</c>. A sentence has spaces in it. Checking only the adjacent
    /// characters was tried first and let three matches through, because a translated line
    /// holds the word several times and only one of them needs to sit against punctuation.
    /// </para>
    /// <para>
    /// Confined to quoted text, so ordinary code naming a cipher is untouched, and to matches
    /// carrying a lowercase letter. An algorithm is written <c>DES</c> or <c>des</c> and never
    /// <c>Des</c>, so title case is a sentence beginning rather than a cipher: two of the
    /// three that survived the first attempt were "Des privilèges administrateur…".
    /// </para>
    /// </remarks>
    private static bool IsWordInProse(Match match, RuleContext context)
    {
        if (!match.Value.Any(char.IsLower)
            || !Heuristics.IsInsideStringLiteral(context, match.Index))
        {
            return false;
        }

        var line = context.LineFor(match);
        var at = context.OffsetInLine(match.Index);

        if (at <= 0 || at >= line.Length)
        {
            return false;
        }

        var opening = line.LastIndexOfAny(['"', '\''], at - 1) + 1;
        var closing = line.IndexOfAny(['"', '\''], at);

        return line[opening..(closing < 0 ? line.Length : closing)].Any(char.IsWhiteSpace);
    }

    /// <summary>The statement keyword a SQL match opens with. See <c>IsProseNotSql</c>.</summary>
    private static readonly Regex LeadingKeyword = PatternRule.Compile(
        """^\s*(SELECT|INSERT|UPDATE|DELETE|DROP)""",
        RegexOptions.IgnoreCase);

    /// <summary>A clause keyword beyond the opening one, which prose rarely carries.</summary>
    private static readonly Regex SecondClauseKeyword = PatternRule.Compile(
        """\b(WHERE|VALUES|SET|JOIN|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|RETURNING)\b""",
        RegexOptions.IgnoreCase);

    /// <inheritdoc cref="SecretRules.All"/>
    public static IReadOnlyList<IRule> All =>
    [
        SqlInjection,
        DynamicCodeEvaluation,
        CommandInjection,
        UnsafeDeserialisation,
        WeakPasswordHashing,
        WeakCipher,
        InsecureRandomForSecurity,
        ArchiveExtractionWithoutPathCheck,
    ];

    private static PatternRule SqlInjection { get; } = new()
    {
        Id = "VC-CODE-001",
        Title = "SQL query built by string concatenation",
        Severity = Severity.Critical,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description =
            "A SQL statement is assembled from interpolated or concatenated values. If any part "
            + "of that comes from user input, the input is executed as SQL, which allows reading, "
            + "modifying, or destroying the whole database.",
        Remediation =
            "Use parameterised queries and pass values as parameters rather than building the "
            + "statement text. Every mainstream database library supports this, and it is not "
            + "meaningfully more work than concatenation.",
        // Requires the full statement shape (SELECT..FROM, UPDATE..SET) rather than a bare
        // keyword. Matching the keyword alone fired on ordinary English: a WPF trace string
        // reading "Default update trigger resolved to {1}" was reported as SQL injection
        // because "update" was followed by a format placeholder.
        UserDescription =
            "The application builds database commands by gluing text together. If any of that "
            + "text comes from something you opened or typed, a carefully crafted input can make it "
            + "run a different command than intended, which can expose or destroy the data this app "
            + "is holding.",
        UserRemediation ="Be careful about opening files from people you do not know in this application.",
        Pattern = PatternRule.Compile(
            """
            (?:SELECT\s+[\w*,.\s()`'"\[\]]{1,120}?\s+FROM\s
            |UPDATE\s+[\w.`'"\[\]]{1,60}\s+SET\s
            |INSERT\s+INTO\s+[\w.`'"\[\]]{1,60}
            |DELETE\s+FROM\s+[\w.`'"\[\]]{1,60}
            |DROP\s+TABLE\s+[\w.`'"\[\]]{1,60})
            # Quotes are allowed in the gap: SQL wraps interpolated values in them, as in
            # WHERE token = '${token}'. The statement shape above is what provides precision.
            [^;\r\n]{0,200}?
            (?:\$\{[^}]+\}|"\s*\+\s*\w|'\s*\+\s*\w|\+\s*\w+\s*\+|%s|\{\d+\}|\{\w+\})
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) =>
            Heuristics.IsInLineComment(context, match.Index) || IsProseNotSql(match.Value),
    };

    /// <summary>
    /// Distinguishes a SQL statement from an English sentence containing the same words.
    /// </summary>
    /// <remarks>
    /// Requiring the full statement shape was not enough on its own. A dependency-injection
    /// library's error message, "Unable to select single public constructor from
    /// implementation type {0}", satisfies SELECT..FROM followed by a placeholder and was
    /// reported as SQL injection.
    /// <para>
    /// Two signals separate them reliably: code that builds SQL almost always writes the
    /// keywords in upper case, and a real statement almost always carries a second clause
    /// keyword. Prose has neither. Either signal alone is enough to accept the match.
    /// </para>
    /// </remarks>
    private static bool IsProseNotSql(string matched)
    {
        var leading = LeadingKeyword.Match(matched);

        if (leading.Success && leading.Value.Trim() == leading.Value.Trim().ToUpperInvariant())
        {
            return false;
        }

        return !SecondClauseKeyword.IsMatch(matched);
    }

    private static PatternRule DynamicCodeEvaluation { get; } = new()
    {
        Id = "VC-CODE-002",
        Title = "Dynamic code evaluation on a constructed string",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application evaluates a string as code, and that string is built at runtime. "
            + "Any input reaching it is executed with the application's full privileges.",
        Remediation =
            "Replace the evaluation with an explicit branch or a lookup table. If the value is "
            + "data, parse it with a data parser such as JSON.parse rather than executing it.",
        UserDescription =
            "The application builds a piece of code as text and then runs it. If any part of that "
            + "text comes from a file you open or a server it talks to, then whoever controls that "
            + "content decides what runs on your machine.",
        UserRemediation ="Only open files from sources you trust in this application.",
        Pattern = PatternRule.Compile(
            """
            (?:\beval\s*\(\s*(?![)'"`]\s*\))
            |new\s+Function\s*\(
            |setTimeout\s*\(\s*["'`][^"'`]*\$\{
            |\bexec\s*\(\s*f["'])
            """,
            RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) =>
            Heuristics.IsGeneratedCode(context.File.RelativePath)
            || Heuristics.IsInLineComment(context, match.Index),
    };

    /// <summary>
    /// The modules whose <c>exec</c> hands its argument to a shell, as the quoted specifier a
    /// require or an import names them by.
    /// </summary>
    private const string ShellModule = """["'](?:node:)?(?:child_process|shelljs)["']""";

    /// <summary>
    /// The right-hand side of an assignment that loads a shell module, however the require was
    /// wrapped: plain, inside a bundler's interop helper such as <c>__toESM(..)</c>, or as
    /// webpack writes it, <c>__webpack_require__(/*! child_process */ "child_process")</c>.
    /// </summary>
    private const string LoadsShellModule =
        $$"""=\s*(?:await\s+)?(?:[\w$.]+\s*\(\s*(?:/\*[^*]*\*/\s*)?)+{{ShellModule}}""";

    /// <summary>A quoted string on one line, with escapes honoured.</summary>
    private const string QuotedString = """(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*')""";

    /// <summary>
    /// A name a file gives to a shell module: <c>const cp = require("child_process")</c>,
    /// <c>this.shell = require("shelljs")</c> or <c>import * as cp from "node:child_process"</c>.
    /// </summary>
    private static readonly Regex ShellModuleName = PatternRule.Compile(
        $$"""
        (?<![\w$.])(?<name>[\w$]+(?:\.[\w$]+)*)\s*{{LoadsShellModule}}
        |import\s+(?:\*\s+as\s+)?(?<name>[\w$]+)\s+from\s*{{ShellModule}}
        """,
        RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// <c>exec</c> or <c>execSync</c> taken out of a shell module under its own name, which is
    /// what makes a bare call to it the shell rather than some other function called exec.
    /// </summary>
    /// <remarks>
    /// The destructuring form is anchored on the word and looks back for the brace, rather than
    /// starting at every brace and reading forward, so a bundle costs one pass for the word.
    /// </remarks>
    private static readonly Regex ShellExecImport = PatternRule.Compile(
        $$"""
        (?<=\{[^{}]{0,200})\bexec(?:Sync)?\b[^{}]{0,200}\}\s*{{LoadsShellModule}}
        |import\s*\{[^{}]{0,200}\bexec(?:Sync)?\b[^{}]{0,200}\}\s*from\s*{{ShellModule}}
        |\bexec(?:Sync)?\s*{{LoadsShellModule}}\s*\)\s*\.\s*exec(?:Sync)?\b
        """,
        RegexOptions.IgnorePatternWhitespace);

    private static PatternRule CommandInjection { get; } = new()
    {
        Id = "VC-CODE-003",
        Title = "Shell command built from interpolated values",
        Severity = Severity.Critical,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "A shell command is assembled from interpolated or concatenated values. Because the "
            + "string goes to a shell, characters such as ; && | and backticks in the input start "
            + "new commands, which run with the application's privileges.",
        Remediation =
            "Pass the program and its arguments as a list rather than a single string, so no shell "
            + "parses it. In Node use execFile or spawn with an argument array; in .NET set "
            + "ProcessStartInfo.ArgumentList; in Python use subprocess with a list and shell=False.",
        UserDescription =
            "The application builds system commands by pasting values into them. If one of those "
            + "values comes from a file, a link, or a server response, someone who controls it can "
            + "get commands of their choosing to run on your computer.",
        UserRemediation ="Only open files and links from sources you trust in this application.",
        // Node's exec is reached four ways: off the module (child_process.exec, or a bundler's
        // child_process_1.exec), off a require, through the (0, x.exec)(..) call TypeScript and
        // Babel emit, and bare after const { exec } = require("child_process"). Only the first
        // used to be matched with concatenation, so the most common idiom, a bare
        // exec("ping " + req.query.host), let a test Express app score 100/100.
        //
        // Matching exec by name alone would pull in RegExp and SQLite, which both have an exec
        // that takes concatenated strings. The old template-literal branch already reported
        // both in a sweep of 13,000 node_modules files. IsSomeOtherExec keeps a call only when
        // the file binds that exec to a shell module. The concatenation must also reach
        // something other than another literal, since a long command split across lines is
        // still a constant.
        Pattern = PatternRule.Compile(
            $$"""
            (?<exec>
              (?:(?<module>require\s*\(\s*{{ShellModule}}\s*\))\.exec(?:Sync)?\s*\(
              |(?<![\w$.])(?<receiver>[\w$]+(?:\.[\w$]+)*)\.exec(?:Sync)?\s*\(
              |\(\s*0\s*,\s*(?<receiver>[\w$]+(?:\.[\w$]+)*)\.exec(?:Sync)?\s*\)\s*\(
              |(?<![\w$.\#])exec(?:Sync)?\s*\()
              \s*(?:`[^`]*\$\{|{{QuotedString}}(?:\s*\+\s*{{QuotedString}})*\s*\+\s*(?=[\w$(\[])))
            |os\.system\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+])
            |subprocess\.\w+\([^)]*shell\s*=\s*True
            |Process\.Start\s*\(\s*[$"][^"]*\{
            """,
            RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) =>
            Heuristics.IsInLineComment(context, match.Index) || IsSomeOtherExec(match, context),
    };

    /// <summary>
    /// Whether an <c>exec</c> call belongs to something other than a shell.
    /// </summary>
    /// <remarks>
    /// The answer comes from what the file binds. A file that never loads a shell module has no
    /// shell exec to call, whatever its functions are named, and a receiver counts as the shell
    /// only when the file assigns a shell module to that name. Bundlers name the binding after
    /// the module (<c>child_process_1</c>, <c>import_child_process.default</c>), so a receiver
    /// carrying the module's name is taken at its word, as <c>child_process.exec</c> always was.
    /// </remarks>
    private static bool IsSomeOtherExec(Match match, RuleContext context)
    {
        if (!match.Groups["exec"].Success || match.Groups["module"].Success)
        {
            return false;
        }

        var receiver = match.Groups["receiver"];

        if (receiver.Success && receiver.Value.Contains("child_process", StringComparison.Ordinal))
        {
            return false;
        }

        var imports = ShellImports.Of(context);

        return receiver.Success ? !imports.Names.Contains(receiver.Value) : !imports.ExecByName;
    }

    /// <summary>
    /// What one file binds to a shell module, read once and shared by every exec call in it.
    /// </summary>
    /// <remarks>
    /// Cached per file because the answer is a property of the file, and a bundle can hold
    /// thousands of calls to some exec that would otherwise each search it again.
    /// </remarks>
    private sealed class ShellImports
    {
        private static readonly ConditionalWeakTable<RuleContext, ShellImports> ByFile = new();

        private static readonly ShellImports None = new()
        {
            Names = new HashSet<string>(),
            ExecByName = false,
        };

        /// <summary>Names assigned a shell module, such as <c>cp</c> or <c>this.shell</c>.</summary>
        public required IReadOnlySet<string> Names { get; init; }

        /// <summary>Whether exec or execSync was imported under its own name.</summary>
        public required bool ExecByName { get; init; }

        public static ShellImports Of(RuleContext context) => ByFile.GetValue(context, Read);

        private static ShellImports Read(RuleContext context)
        {
            var content = context.Content;

            // Most files never name a shell module, and a substring search settles those without
            // running either pattern over the whole file.
            if (!content.Contains("child_process", StringComparison.Ordinal)
                && !content.Contains("shelljs", StringComparison.Ordinal))
            {
                return None;
            }

            try
            {
                return new ShellImports
                {
                    Names = ShellModuleName.Matches(content)
                        .Select(m => m.Groups["name"].Value)
                        .ToHashSet(StringComparer.Ordinal),
                    ExecByName = ShellExecImport.IsMatch(content),
                };
            }
            catch (RegexMatchTimeoutException)
            {
                // Reported as the rule not finishing on this file, the same as its own pattern
                // timing out, rather than guessed in either direction.
                throw new RuleTimeoutException(CommandInjection.Id, context.File.RelativePath);
            }
        }
    }

    private static PatternRule UnsafeDeserialisation { get; } = new()
    {
        Id = "VC-CODE-004",
        Title = "Unsafe deserialisation of untrusted data",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application uses a deserialiser that can construct arbitrary types and invoke "
            + "code while reading. A crafted payload can achieve code execution before the "
            + "application ever inspects the resulting object.",
        Remediation =
            "Use a data-only format and parser: System.Text.Json in .NET, yaml.safe_load in "
            + "Python, and never pickle for data that crosses a trust boundary.",
        UserDescription =
            "The application rebuilds saved data back into live objects without checking it "
            + "first. With this pattern, opening a file that somebody prepared for the purpose can "
            + "start their code running on your machine rather than simply loading their data.",
        UserRemediation ="Do not open project or save files sent to you by people you do not know.",
        Pattern = PatternRule.Compile(
            """
            (?:BinaryFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter
            |pickle\.loads?\s*\(
            |yaml\.load\s*\((?![^)]*SafeLoader)
            |TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Objects|Auto))
            """,
            RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) =>
        {
            var line = context.LineFor(match);

            // A runtime switch that turns the dangerous behaviour off is the mitigation, not
            // the vulnerability. Observed firing on the .NET runtimeconfig entry
            // "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization": false,
            // which is exactly the setting that disables it.
            return line.Contains(": false", StringComparison.OrdinalIgnoreCase)
                || line.Contains("=false", StringComparison.OrdinalIgnoreCase)
                || line.Contains("= false", StringComparison.OrdinalIgnoreCase)
                || Heuristics.IsInLineComment(context, match.Index);
        },
    };

    private static PatternRule WeakPasswordHashing { get; } = new()
    {
        Id = "VC-CODE-005",
        Title = "Password hashed with a fast general-purpose digest",
        Severity = Severity.High,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description =
            "Passwords are hashed with MD5 or SHA-1. These are designed to be fast, which is the "
            + "opposite of what password storage needs: commodity hardware tries billions of "
            + "candidates per second, so a stolen database of these hashes is cracked quickly.",
        Remediation =
            "Use a purpose-built password hash with a work factor: bcrypt, scrypt, or Argon2id. "
            + "In .NET, Rfc2898DeriveBytes with a high iteration count is acceptable.",
        UserDescription =
            "If you have an account with this application, your password is stored using a method "
            + "that modern hardware can work through very quickly. Should that store ever be "
            + "stolen, guessing your password from it is far easier than it should be.",
        UserRemediation ="Use a password here that you do not use anywhere else.",
        Pattern = PatternRule.Compile(
            """
            (?:MD5|SHA1|SHA-1)[^;\r\n]{0,80}?(?:password|passwd|pwd)
            |(?:password|passwd|pwd)[^;\r\n]{0,80}?(?:MD5|SHA1|SHA-1)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) => Heuristics.IsInLineComment(context, match.Index),
    };

    private static PatternRule WeakCipher { get; } = new()
    {
        Id = "VC-CODE-006",
        Title = "Broken or misused cipher",
        Severity = Severity.Medium,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application uses DES, RC4, or ECB mode. DES and RC4 are broken, and ECB leaks "
            + "structure because identical plaintext blocks produce identical ciphertext blocks.",
        Remediation =
            "Use AES in an authenticated mode such as GCM, which provides both confidentiality "
            + "and tamper detection.",
        UserDescription =
            "The application protects some of its data with an encryption method that is no "
            + "longer considered sound. Whatever it is scrambling, which may include things you "
            + "have given it, is not as protected as the presence of encryption suggests.",
        Pattern = PatternRule.Compile(
            """(?:\bDES(?:CryptoServiceProvider)?\b|\bRC4\b|CipherMode\.ECB|MODE_ECB|["']AES-\d+-ECB["'])""",
            RegexOptions.IgnoreCase),
        Ignore = (match, context) =>
        {
            // TripleDES is weak but not broken in the same way, and shares the substring.
            if (match.Value.Contains("3DES", StringComparison.OrdinalIgnoreCase)
                || match.Value.Contains("TripleDES", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // "des" is an ordinary word in German, French and Spanish, and a translated
            // interface carries hundreds of them: "Verwaltung des Kontextmenüs" is a menu
            // label, not a cipher. Found on a real application, where its translation bundle
            // produced 270 matches and twenty Medium findings, none of them real.
            //
            // A cipher name is never a word between two spaces. Lowercase does appear
            // legitimately, but as the whole quoted value ('des') or a hyphenated OpenSSL
            // spec ('des-ede3-cbc'), and neither of those is delimited this way.
            if (IsWordInProse(match, context))
            {
                return true;
            }

            // Naming a cipher is not using one. Observed firing on the members of
            // SharpZipLib's EncryptionAlgorithm enum, where "Des = 26113," is a declaration
            // of a value the library can recognise, not an algorithm the application chose.
            return EnumMemberDeclaration.IsMatch(context.LineFor(match))
                || Heuristics.IsInLineComment(context, match.Index);
        },
    };


    private static PatternRule InsecureRandomForSecurity { get; } = new()
    {
        Id = "VC-CODE-007",
        Title = "Security value generated from a predictable random source",
        Severity = Severity.High,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description =
            "A token, session identifier, or password is derived from a general-purpose random "
            + "number generator. These are seeded predictably and are not designed to resist "
            + "analysis, so an attacker who observes a few outputs can predict later ones.",
        Remediation =
            "Use a cryptographic generator: crypto.randomBytes in Node, secrets in Python, or "
            + "RandomNumberGenerator in .NET.",
        UserDescription =
            "The application generates security values such as tokens or reset links using a "
            + "shortcut that produces predictable results. Someone targeting your account could "
            + "work out a value they should not be able to guess.",
        Pattern = PatternRule.Compile(
            """
            (?:token|session|secret|password|nonce|salt|otp|verification|reset)
            \w*\s*[:=][^;\r\n]{0,60}?
            (?:Math\.random\s*\(|new\s+Random\s*\(|random\.(?:random|randint|choice)\s*\()
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };

    private static PatternRule ArchiveExtractionWithoutPathCheck { get; } = new()
    {
        Id = "VC-CODE-008",
        Title = "Archive extracted without validating entry paths",
        Severity = Severity.High,
        UserSeverity = Severity.High,
        Category = FindingCategory.CodeSafety,
        Description =
            "The application writes archive entries to disk using the path stored in the archive. "
            + "An entry named with traversal segments escapes the destination directory and "
            + "overwrites arbitrary files, which is commonly used to plant a startup item or "
            + "replace a binary the user later runs.",
        Remediation =
            "Resolve each destination to its full path and confirm it is still inside the target "
            + "directory before writing. In .NET, ExtractToDirectory performs this check; manual "
            + "loops over entries do not.",
        UserDescription =
            "The application unpacks archive files without checking where the contents claim to "
            + "go. An archive built for the purpose can drop files outside the folder you expected, "
            + "anywhere the app can write, which is a known way to plant something that later runs.",
        UserRemediation ="Do not open zip or archive files from people you do not know in this application.",
        Pattern = PatternRule.Compile(
            """
            (?:entry\.FullName|entry\.filename|zipEntry\.Name|member\.name)
            [^;\r\n]{0,60}?(?:Path\.Combine|os\.path\.join|path\.join)
            """,
            RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace),
    };
}
