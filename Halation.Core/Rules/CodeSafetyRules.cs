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
        Pattern = PatternRule.Compile(
            """
            (?:child_process\.(?:exec|execSync)\s*\(\s*[`"'][^`"']*(?:\$\{|"\s*\+|'\s*\+)
            |\bexec\s*\(\s*`[^`]*\$\{
            |os\.system\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+])
            |subprocess\.\w+\([^)]*shell\s*=\s*True
            |Process\.Start\s*\(\s*[$"][^"]*\{)
            """,
            RegexOptions.IgnorePatternWhitespace),
        Ignore = (match, context) => Heuristics.IsInLineComment(context, match.Index),
    };

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
