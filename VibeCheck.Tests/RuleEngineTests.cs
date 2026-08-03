using System.Diagnostics;
using System.Text;
using System.Text.Json;

using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;

namespace VibeCheck.Tests;

public class RuleEngineTests
{
    private static readonly RuleEngine Engine = new();

    private static IReadOnlyList<Finding> Scan(
        string content,
        string path = "src/app.js",
        SourceLanguage? language = null)
    {
        var file = new RecoveredFile
        {
            RelativePath = path,
            Content = content,
            Language = language ?? RecoveredFile.LanguageOf(path),
        };

        return Engine.Analyse([file]).Findings;
    }

    private static bool Fired(string ruleId, string content, string path = "src/app.js") =>
        Scan(content, path).Any(f => f.RuleId == ruleId);

    // ---- Secrets: true positives ------------------------------------------

    [Fact]
    public void AwsAccessKey_IsDetected()
    {
        var findings = Scan("""const key = "AKIAIOSFODNN7EXAMPLE";""");

        var finding = Assert.Single(findings, f => f.RuleId == "VC-SEC-002");
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(FindingCategory.Secrets, finding.Category);
        Assert.Equal(1, finding.Line);
    }

    [Fact]
    public void PrivateKeyBlock_IsDetected() =>
        Assert.True(Fired("VC-SEC-001", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n"));

    [Fact]
    public void StripeLiveKey_IsDetected() =>
        Assert.True(Fired("VC-SEC-003", """stripe.setKey("sk_live_4eC39HqLyjWDarjtT1zdp7dcabcd");"""));

    [Fact]
    public void GenericHighEntropySecret_IsDetected() =>
        Assert.True(Fired("VC-SEC-010", """const apiKey = "7Xq2mVn8Kp4Rt6Yw9Zb3";"""));

    /// <summary>
    /// Reports must never quote a live credential in full, since they get pasted into issue
    /// trackers and screenshots.
    /// </summary>
    [Fact]
    public void Evidence_MasksTheSecret()
    {
        const string secret = "AKIAIOSFODNN7EXAMPLE";

        var finding = Scan($"""const key = "{secret}";""").Single(f => f.RuleId == "VC-SEC-002");

        Assert.NotNull(finding.Evidence);
        Assert.DoesNotContain(secret, finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("****", finding.Evidence, StringComparison.Ordinal);
        // A short prefix survives so the developer can tell which key to rotate.
        Assert.Contains("AKIA", finding.Evidence, StringComparison.Ordinal);
    }

    // ---- The reader's own key ----------------------------------------------

    /// <summary>
    /// The other direction of the same promise. Everything above keeps somebody else's secret
    /// out of a report; this keeps the reader's own billing key out of one, because the text
    /// that carries it is an exception message they are being shown in order to paste it
    /// somewhere public.
    /// </summary>
    [Fact]
    public void Scrub_RemovesTheReadersOwnApiKey()
    {
        const string key = "sk-ant-api03-AbCdEf0123456789_xyz-QWERTY";

        var scrubbed = Redaction.Scrub($"The deep pass failed: 401 unauthorised for {key}.");

        Assert.DoesNotContain(key, scrubbed, StringComparison.Ordinal);
        Assert.DoesNotContain("AbCdEf", scrubbed, StringComparison.Ordinal);
        Assert.Contains("[redacted]", scrubbed, StringComparison.Ordinal);

        // The rest of the message survives, or the redaction has cost the reader the only
        // thing the message was for.
        Assert.Contains("401 unauthorised", scrubbed, StringComparison.Ordinal);
    }

    /// <summary>
    /// A failure explains itself with paths, model names and status codes. A pattern broad
    /// enough to eat those would make every diagnostic message useless to protect against a
    /// credential that is not in it.
    /// </summary>
    [Theory]
    [InlineData("The deep pass failed: 529 overloaded_error from claude-opus-5.")]
    [InlineData("Could not write the report: access denied to C:\\Users\\x\\Desktop\\report.md.")]
    [InlineData("No Claude Code installation was found on this machine.")]
    public void Scrub_LeavesAnOrdinaryFailureIntact(string message) =>
        Assert.Equal(message, Redaction.Scrub(message));

    /// <summary>
    /// Applied where the text is built, not where it is shown, so a message added later
    /// inherits it rather than having to remember to ask.
    /// </summary>
    [Fact]
    public void ADeepPassLimitation_IsScrubbedOnItsWayIn()
    {
        var review = new FileReview
        {
            Limitation = "The deep pass failed: bad key sk-ant-api03-LiveKeyMaterial123.",
        };

        Assert.NotNull(review.Limitation);
        Assert.DoesNotContain("LiveKeyMaterial", review.Limitation, StringComparison.Ordinal);

        var result = new DeepPassResult
        {
            Limitations = ["Answered by sk-ant-api03-AnotherLiveKey456 somehow."],
        };

        Assert.DoesNotContain("AnotherLiveKey", result.Limitations[0], StringComparison.Ordinal);
    }

    // ---- Secrets: false positives -----------------------------------------

    [Theory]
    [InlineData("""const apiKey = process.env.API_KEY;""")]
    [InlineData("""const apiKey = import.meta.env.VITE_KEY;""")]
    [InlineData("""api_key = os.getenv("API_KEY")""")]
    [InlineData("""var apiKey = Environment.GetEnvironmentVariable("API_KEY");""")]
    [InlineData("""apiKey: "${API_KEY}",""")]
    public void CredentialsReadFromConfiguration_AreNotFlagged(string line) =>
        Assert.False(Fired("VC-SEC-010", line), $"false positive on: {line}");

    [Theory]
    [InlineData("""const apiKey = "YOUR_API_KEY_HERE";""")]
    [InlineData("""const apiKey = "your-api-key";""")]
    [InlineData("""const apiKey = "xxxxxxxxxxxxxxxx";""")]
    [InlineData("""const apiKey = "changeme12345678";""")]
    [InlineData("""const apiKey = "0000000000000000";""")]
    [InlineData("""const password = "example_password";""")]
    public void PlaceholderValues_AreNotFlagged(string line) =>
        Assert.False(Fired("VC-SEC-010", line), $"false positive on: {line}");

    [Fact]
    public void CommentedOutCredential_IsNotFlaggedByTheGenericRule() =>
        Assert.False(Fired("VC-SEC-010", """// const apiKey = "7Xq2mVn8Kp4Rt6Yw9Zb3";"""));

    [Fact]
    public void ShortOrLowEntropyValues_AreNotFlagged()
    {
        Assert.False(Fired("VC-SEC-010", """const apiKey = "abc";"""));
        Assert.False(Fired("VC-SEC-010", """const token = "aaaaaaaaaaaaaaaa";"""));
    }

    // ---- Supabase: the anon/service_role distinction ----------------------

    /// <summary>
    /// The two Supabase keys are visually identical and only the decoded role tells them
    /// apart. Getting this wrong in either direction is bad: missing service_role hides a
    /// total database compromise, and flagging anon cries wolf on a key meant to be public.
    /// </summary>
    [Fact]
    public void SupabaseServiceRoleKey_IsDetectedAsCritical()
    {
        var findings = Scan($"""const supabase = createClient(url, "{Jwt("service_role")}");""");

        var finding = Assert.Single(findings, f => f.RuleId == "VC-SEC-011");
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("bypasses row-level security", finding.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void SupabaseAnonKey_IsNotFlagged() =>
        Assert.False(Fired("VC-SEC-011", $"""const supabase = createClient(url, "{Jwt("anon")}");"""));

    [Fact]
    public void MalformedJwt_DoesNotThrow() =>
        Assert.False(Fired("VC-SEC-011", """const t = "eyJhbGciOiJIUzI1NiJ9.notvalidbase64!!!.sig";"""));

    // ---- Configuration ----------------------------------------------------

    [Theory]
    [InlineData("VC-CFG-001", """{"rules": {".read": true, ".write": true}}""", "database.rules.json")]
    [InlineData("VC-CFG-002", "new BrowserWindow({ webPreferences: { nodeIntegration: true } })", "main.js")]
    [InlineData("VC-CFG-003", "new BrowserWindow({ webPreferences: { contextIsolation: false } })", "main.js")]
    [InlineData("VC-CFG-005", "const agent = new https.Agent({ rejectUnauthorized: false });", "api.js")]
    [InlineData("VC-CFG-008", """server.listen(3000, "0.0.0.0");""", "server.js")]
    public void ConfigurationRules_Fire(string ruleId, string content, string path) =>
        Assert.True(Fired(ruleId, content, path), $"{ruleId} did not fire");

    [Fact]
    public void FirebaseAllowIfTrue_IsDetected() =>
        Assert.True(Fired("VC-CFG-001", "allow read, write: if true;", "firestore.rules"));

    [Theory]
    [InlineData("""xmlns="http://www.w3.org/2000/svg" """)]
    [InlineData("""const schema = "http://schemas.microsoft.com/winfx/2006/xaml";""")]
    [InlineData("""const local = "http://localhost:3000/api";""")]
    public void NonNetworkHttpUrls_AreNotFlaggedAsCleartext(string line) =>
        Assert.False(Fired("VC-CFG-007", line), $"false positive on: {line}");

    [Fact]
    public void RealCleartextEndpoint_IsFlagged() =>
        Assert.True(Fired("VC-CFG-007", """fetch("http://api.example.com/v1/users");"""));

    // ---- Code safety ------------------------------------------------------

    [Theory]
    [InlineData("VC-CODE-001", """db.query(`SELECT * FROM users WHERE id = ${userId}`);""")]
    [InlineData("VC-CODE-002", "const fn = new Function(userInput);")]
    [InlineData("VC-CODE-003", "child_process.exec(`convert ${file} out.png`);")]
    [InlineData("VC-CODE-007", "const token = Math.random().toString(36);")]
    public void CodeSafetyRules_Fire(string ruleId, string content) =>
        Assert.True(Fired(ruleId, content), $"{ruleId} did not fire");

    [Fact]
    public void ParameterisedQuery_IsNotFlaggedAsInjection() =>
        Assert.False(Fired("VC-CODE-001", """db.query("SELECT * FROM users WHERE id = ?", [userId]);"""));

    [Fact]
    public void UnsafeDeserialisation_IsDetected() =>
        Assert.True(Fired("VC-CODE-004", "var f = new BinaryFormatter();", "Program.cs"));

    // ---- Malicious behaviour and the blocking guarantee -------------------

    [Fact]
    public void BrowserPasswordAccess_IsBlocking()
    {
        var findings = Scan(
            """const p = path.join(appData, "Google/Chrome/User Data/Default/Login Data");""");

        var finding = Assert.Single(findings, f => f.RuleId == "VC-MAL-001");
        Assert.True(finding.IsBlocking);
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    [Fact]
    public void WalletFileAccess_IsBlocking()
    {
        var finding = Assert.Single(
            Scan("""const w = path.join(home, "Exodus/exodus.wallet");"""),
            f => f.RuleId == "VC-MAL-003");

        Assert.True(finding.IsBlocking);
    }

    /// <summary>
    /// Blocking is the strongest claim the report makes. It must come only from rules where
    /// the installing user is the one at risk, never from developer-side problems like a
    /// leaked key, however severe those are.
    /// </summary>
    [Fact]
    public void OnlyMaliciousBehaviourRules_CanBlock()
    {
        var blockingIds = RuleEngine.DefaultRules
            .OfType<PatternRule>()
            .Where(r => r.IsBlocking)
            .Select(r => r.Id)
            .ToList();

        Assert.NotEmpty(blockingIds);
        Assert.All(blockingIds, id =>
            Assert.StartsWith("VC-MAL-", id, StringComparison.Ordinal));
    }

    [Fact]
    public void LeakedCredentials_AreCriticalButNotBlocking()
    {
        var findings = Scan($"""
            const key = "AKIAIOSFODNN7EXAMPLE";
            const sb = createClient(url, "{Jwt("service_role")}");
            """);

        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.False(f.IsBlocking));
    }

    [Fact]
    public void StartupPersistence_IsReportedButNotBlocking()
    {
        var finding = Assert.Single(
            Scan("""reg.add("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name);""", "setup.cs"),
            f => f.RuleId == "VC-MAL-006");

        Assert.False(finding.IsBlocking);
    }

    // ---- Test-file handling -----------------------------------------------

    [Fact]
    public void FindingsInTestFiles_AreSoftened()
    {
        var production = Scan("const fn = new Function(input);", "src/app.js")
            .Single(f => f.RuleId == "VC-CODE-002");
        var test = Scan("const fn = new Function(input);", "src/__tests__/app.test.js")
            .Single(f => f.RuleId == "VC-CODE-002");

        Assert.True(test.Severity < production.Severity);
        Assert.Contains("test or example", test.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A key committed to a fixture is published exactly as widely as one in production
    /// code, so the softening must not apply to it.
    /// </summary>
    [Fact]
    public void SecretsInTestFiles_AreNotSoftened()
    {
        var production = Scan("""const k = "AKIAIOSFODNN7EXAMPLE";""", "src/app.js")
            .Single(f => f.RuleId == "VC-SEC-002");
        var test = Scan("""const k = "AKIAIOSFODNN7EXAMPLE";""", "test/app.test.js")
            .Single(f => f.RuleId == "VC-SEC-002");

        Assert.Equal(production.Severity, test.Severity);
    }

    // ---- Engine behaviour --------------------------------------------------

    [Fact]
    public void RuleIds_AreUnique()
    {
        var duplicates = RuleEngine.DefaultRules
            .GroupBy(r => r.Id)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void RepeatedMatchesOnOneLine_ProduceOneFinding()
    {
        var findings = Scan(
            """const a = "AKIAIOSFODNN7EXAMPLE", b = "AKIAIOSFODNN7EXAMPLF";""");

        Assert.Single(findings, f => f.RuleId == "VC-SEC-002");
    }

    [Fact]
    public void FindingsAreOrderedWorstFirst()
    {
        var findings = Scan("""
            fetch("http://api.example.com/x");
            const k = "AKIAIOSFODNN7EXAMPLE";
            """);

        Assert.True(findings.Count >= 2);
        Assert.Equal(findings.OrderByDescending(f => f.Severity).Select(f => f.RuleId), findings.Select(f => f.RuleId));
    }

    [Fact]
    public void EmptyInput_ProducesNoFindings() =>
        Assert.Empty(Engine.Analyse([]).Findings);

    /// <summary>
    /// The engine runs regular expressions over content it assumes is hostile, so a
    /// pathological input must not stall the scan.
    /// </summary>
    [Fact]
    public void PathologicalInput_CompletesPromptly()
    {
        var hostile = new StringBuilder();
        hostile.Append("const q = \"SELECT ");
        hostile.Append(new string('a', 40_000));
        hostile.Append("' + '");
        hostile.Append(new string('b', 40_000));
        hostile.Append("\";\n");
        hostile.Append(new string('x', 200_000));

        var stopwatch = Stopwatch.StartNew();
        Engine.Analyse([new RecoveredFile
        {
            RelativePath = "hostile.js",
            Content = hostile.ToString(),
            Language = SourceLanguage.JavaScript,
        }]);
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(30),
            $"analysis took {stopwatch.Elapsed.TotalSeconds:F1}s");
    }

    [Fact]
    public void ManyFiles_AreAnalysedInParallelWithoutLoss()
    {
        var files = Enumerable.Range(0, 400).Select(i => new RecoveredFile
        {
            RelativePath = $"src/file{i}.js",
            Content = """const key = "AKIAIOSFODNN7EXAMPLE";""",
            Language = SourceLanguage.JavaScript,
        }).ToList();

        var result = Engine.Analyse(files);

        Assert.Equal(400, result.FilesAnalysed);
        Assert.Equal(400, result.Findings.Count(f => f.RuleId == "VC-SEC-002"));
    }

    /// <summary>Builds a Supabase-shaped JWT asserting the given role.</summary>
    private static string Jwt(string role)
    {
        static string Segment(object value) =>
            Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Segment(new { alg = "HS256", typ = "JWT" });
        var payload = Segment(new { iss = "supabase", role, iat = 1700000000, exp = 1900000000 });

        return $"{header}.{payload}.tG7Yk2Qp9Lm4Xv8Nc3Bz1Rw6Ht5Ja0Sd";
    }
}
