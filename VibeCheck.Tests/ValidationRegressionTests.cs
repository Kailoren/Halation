using VibeCheck.Core;
using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;
using VibeCheck.Core.Rules;
using VibeCheck.Core.Scoring;

namespace VibeCheck.Tests;

/// <summary>
/// Regressions for defects found by running the scanner against real, already-audited
/// production applications rather than against synthetic fixtures.
/// </summary>
/// <remarks>
/// Every case here is a bug the synthetic tests passed straight through. They are kept
/// together because they share a cause: assumptions about what a real distribution looks
/// like that only fail on the genuine article.
/// </remarks>
public class ValidationRegressionTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-regress-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    private static Finding Finding(Severity severity) => new()
    {
        RuleId = "VC-TEST",
        Title = "test",
        Severity = severity,
        UserSeverity = severity,
        Category = FindingCategory.CodeSafety,
        Description = "test",
        UserDescription = "test",
    };

    // ---- Zero coverage must not read as a pass ----------------------------

    /// <summary>
    /// Found by scanning a real self-contained single-file application: it yielded no
    /// readable code and the scan reported "100/100, no known issues found".
    /// </summary>
    [Fact]
    public void NothingReadable_IsNotScoredAsPerfect()
    {
        var verdict = ScoreCalculator.Calculate([], coveragePercent: 0);

        Assert.Equal(ScoreBand.InsufficientCoverage, verdict.Band);
        Assert.False(verdict.HasMeaningfulScore);
        Assert.Equal("Not scored", verdict.ScoreDisplay);
        Assert.DoesNotContain("100", verdict.ScoreDisplay, StringComparison.Ordinal);
    }

    [Fact]
    public void FullCoverageWithNoFindings_StillScoresPerfect()
    {
        var verdict = ScoreCalculator.Calculate([], coveragePercent: 100);

        Assert.Equal(ScoreBand.NoKnownIssues, verdict.Band);
        Assert.True(verdict.HasMeaningfulScore);
        Assert.Equal("100/100", verdict.ScoreDisplay);
    }

    /// <summary>
    /// Low coverage suppresses the score, but never suppresses a warning about behaviour
    /// that endangers the user. Those two must stay independent.
    /// </summary>
    [Fact]
    public void BlockingFinding_StillWarnsEvenAtZeroCoverage()
    {
        var blocking = Finding(Severity.Critical) with { IsBlocking = true };

        var verdict = ScoreCalculator.Calculate([blocking], coveragePercent: 0);

        Assert.True(verdict.AdviseAgainstInstall);
        Assert.Equal(ScoreBand.CriticalIssues, verdict.Band);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void CoverageBelowThreshold_SuppressesTheScore(int coverage) =>
        Assert.False(ScoreCalculator.Calculate([], coverage).HasMeaningfulScore);

    [Theory]
    [InlineData(5)]
    [InlineData(60)]
    public void CoverageAtOrAboveThreshold_KeepsTheScore(int coverage) =>
        Assert.True(ScoreCalculator.Calculate([], coverage).HasMeaningfulScore);

    // ---- Framework code must not be reported as the user's ----------------

    /// <summary>
    /// Found by scanning a real self-contained WPF application: 25 findings were reported,
    /// every one of them inside Microsoft's own framework assemblies shipped alongside it.
    /// </summary>
    [Theory]
    [InlineData("PresentationFramework")]
    [InlineData("PresentationCore")]
    [InlineData("WindowsBase")]
    [InlineData("System.Text.Json")]
    [InlineData("Microsoft.Data.Sqlite")]
    [InlineData("mscorlib")]
    [InlineData("netstandard")]
    [InlineData("hostfxr")]
    public void FrameworkAssemblies_AreExcluded(string name) =>
        Assert.True(DotNetRecoveryBackend.IsFrameworkAssembly(name), $"{name} should be excluded");

    [Theory]
    [InlineData("FleetFinder")]
    [InlineData("ColonyTracker")]
    [InlineData("VibeCheck.Core")]
    [InlineData("MyApp")]
    public void ApplicationAssemblies_AreNotExcluded(string name) =>
        Assert.False(DotNetRecoveryBackend.IsFrameworkAssembly(name), $"{name} should be scanned");

    // ---- Rule precision ----------------------------------------------------

    /// <summary>
    /// Found in framework trace strings: "Default update trigger resolved to {1}" was
    /// reported as SQL injection because "update" preceded a format placeholder.
    /// </summary>
    [Theory]
    [InlineData("""new AvTraceDetails(61, new string[1] { "{0}: Default update trigger resolved to {1}" });""")]
    [InlineData("""log.Info($"Update - got raw value {value}");""")]
    [InlineData("""throw new Exception($"Failed to update {name}");""")]
    [InlineData("""// select the item at {0}""")]
    public void EnglishProseContainingSqlKeywords_IsNotFlaggedAsInjection(string line) =>
        Assert.DoesNotContain(
            RunRules(line),
            f => f.RuleId == "VC-CODE-001");

    [Theory]
    [InlineData("""db.query($"SELECT * FROM users WHERE id = {id}");""")]
    [InlineData("""cmd = "UPDATE accounts SET balance = " + amount;""")]
    [InlineData("""sql = `DELETE FROM sessions WHERE token = '${token}'`;""")]
    public void RealSqlConcatenation_IsStillFlagged(string line) =>
        Assert.Contains(RunRules(line), f => f.RuleId == "VC-CODE-001");

    /// <summary>
    /// Found on the Win32 constant FILTER_E_PASSWORD = -2147215613, reported as a connection
    /// string password.
    /// </summary>
    [Theory]
    [InlineData("FILTER_E_PASSWORD = -2147215613,")]
    [InlineData("const int MAX_PASSWORD = 128;")]
    [InlineData("ERROR_PASSWORD_EXPIRED = 0x532;")]
    public void NumericConstantsNamedPassword_AreNotFlagged(string line) =>
        Assert.DoesNotContain(RunRules(line), f => f.RuleId == "VC-SEC-009");

    [Fact]
    public void RealConnectionStringPassword_IsStillFlagged() =>
        Assert.Contains(
            RunRules("""var cs = "Server=db.example.com;Database=app;User Id=admin;Password=Tr0ub4dor3xY;";"""),
            f => f.RuleId == "VC-SEC-009");

    // ---- Packaging ---------------------------------------------------------

    /// <summary>
    /// Every real published application checked was shipping its .pdb, which the project's
    /// own audit checklist calls out and which no source-level rule can see.
    /// </summary>
    [Fact]
    public async Task ShippedDebugSymbols_AreReported()
    {
        var app = Path.Combine(_scratch, "published");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "MyApp.pdb"), "symbols");
        File.WriteAllText(Path.Combine(app, "readme.txt"), "hello");

        var report = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);

        Assert.Contains(report.Findings, f => f.RuleId == "VC-PKG-001");
    }

    [Fact]
    public async Task ShippedEnvFile_IsReportedButExampleIsNot()
    {
        var app = Path.Combine(_scratch, "shipped-env");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, ".env"), "SECRET=abc");
        File.WriteAllText(Path.Combine(app, "index.js"), "run();");

        var withEnv = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);
        Assert.Contains(withEnv.Findings, f => f.RuleId == "VC-PKG-002");

        File.Delete(Path.Combine(app, ".env"));
        File.WriteAllText(Path.Combine(app, ".env.example"), "SECRET=");

        var withExample = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);
        Assert.DoesNotContain(withExample.Findings, f => f.RuleId == "VC-PKG-002");
    }

    // ---- Audit-derived rules ----------------------------------------------

    [Fact]
    public void UnboundedStackAlloc_IsFlagged() =>
        Assert.Contains(
            RunRules("Span<char> buffer = stackalloc char[input.Length];", "Parser.cs"),
            f => f.RuleId == "VC-INPUT-001");

    [Fact]
    public void FixedSizeStackAlloc_IsNotFlagged() =>
        Assert.DoesNotContain(
            RunRules("Span<char> buffer = stackalloc char[256];", "Parser.cs"),
            f => f.RuleId == "VC-INPUT-001");

    [Fact]
    public void ShellOpeningADynamicUrl_IsFlagged() =>
        Assert.Contains(
            RunRules("Process.Start(new ProcessStartInfo(downloadUrl) { UseShellExecute = true });", "Update.cs"),
            f => f.RuleId == "VC-INPUT-002");

    /// <summary>
    /// Every one of these materialises the whole body in a single call, so there is no point
    /// at which the caller could impose a limit.
    /// </summary>
    [Theory]
    [InlineData("var json = await Http.GetStringAsync(url, ct).ConfigureAwait(false);")]
    [InlineData("var bytes = await client.GetByteArrayAsync(uri);")]
    [InlineData("var body = await response.Content.ReadAsStringAsync(ct);")]
    [InlineData("var raw = await response.Content.ReadAsByteArrayAsync();")]
    [InlineData("var text = webClient.DownloadString(address);")]
    public void UnboundedRemoteRead_IsFlagged(string line) =>
        Assert.Contains(RunRules(line, "Client.cs"), f => f.RuleId == "VC-INPUT-004");

    /// <summary>
    /// The recommended fix is a bounded stream copy, so the streaming call it is written in
    /// terms of must not itself be reported.
    /// </summary>
    [Theory]
    [InlineData("await using var stream = await response.Content.ReadAsStreamAsync(ct);")]
    [InlineData("var local = File.ReadAllText(path);")]
    public void BoundedOrLocalRead_IsNotFlagged(string line) =>
        Assert.DoesNotContain(RunRules(line, "Client.cs"), f => f.RuleId == "VC-INPUT-004");

    [Fact]
    public void RemoteReadInAComment_IsNotFlagged() =>
        Assert.DoesNotContain(
            RunRules("// was GetStringAsync(url) before the size cap went in", "Client.cs"),
            f => f.RuleId == "VC-INPUT-004");

    /// <summary>
    /// A helper taking a maximum is the fix this rule recommends, and it keeps the familiar
    /// name so call sites read unchanged. The first application fixed against this rule was
    /// then flagged for its own fix.
    /// </summary>
    [Theory]
    [InlineData("var json = await BoundedHttp.GetStringAsync(Http, url, MaxResponseBytes, ct);")]
    [InlineData("var body = await ReadAsStringAsync(response, maxBytes, ct);")]
    [InlineData("var text = await Http.GetStringAsync(url).WithLimit(1048576);")]
    public void BoundedWrapperAroundARemoteRead_IsNotFlagged(string line) =>
        Assert.DoesNotContain(RunRules(line, "Client.cs"), f => f.RuleId == "VC-INPUT-004");

    /// <summary>
    /// Decompiling an async method emits both the readable await and the state machine behind
    /// it, so one call site arrived as up to three findings pointing at names that exist in no
    /// source file. Measured on a real single-file app: 22 findings became 8.
    /// </summary>
    [Theory]
    [InlineData("val = <result>5__4.Content.ReadAsStringAsync().GetAwaiter();")]
    [InlineData("val2 = <>c__DisplayClass3_0.Content.ReadAsStringAsync().GetAwaiter();")]
    public void DecompiledStateMachineDuplicate_IsNotFlagged(string line) =>
        Assert.DoesNotContain(RunRules(line, "Helper.cs"), f => f.RuleId == "VC-INPUT-004");

    /// <summary>The suppression must not swallow an ordinary generic call.</summary>
    [Fact]
    public void GenericTypeOnTheLine_IsStillFlagged() =>
        Assert.Contains(
            RunRules("List<string> raw = await response.Content.ReadAsStringAsync();", "Helper.cs"),
            f => f.RuleId == "VC-INPUT-004");

    /// <summary>
    /// Packaging checks describe what an application ships, so local build output is not
    /// theirs to report. Dropping in a source folder called bin/Debug/App.pdb "debug symbols
    /// shipped with the release", which is wrong three times over.
    /// </summary>
    [Fact]
    public async Task BuildScratchInASourceTree_IsNotReportedAsShipped()
    {
        var root = Path.Combine(_scratch, "source-tree");
        Directory.CreateDirectory(Path.Combine(root, "bin", "Debug"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        File.WriteAllText(Path.Combine(root, "Program.cs"), "class P { }");
        File.WriteAllText(Path.Combine(root, "bin", "Debug", "App.pdb"), "symbols");
        File.WriteAllText(Path.Combine(root, "obj", "App.pdb"), "symbols");

        var report = await new Scanner().ScanAsync(root, ScanOptions.NoDependencyCheck);

        Assert.DoesNotContain(report.Findings, f => f.RuleId == "VC-PKG-001");
    }

    /// <summary>bin/Release is the release, so a .pdb there is the real mistake.</summary>
    [Fact]
    public async Task SymbolsInReleaseOutput_AreStillReported()
    {
        var root = Path.Combine(_scratch, "release-output");
        Directory.CreateDirectory(Path.Combine(root, "bin", "Release"));
        File.WriteAllText(Path.Combine(root, "Program.cs"), "class P { }");
        File.WriteAllText(Path.Combine(root, "bin", "Release", "App.pdb"), "symbols");

        var report = await new Scanner().ScanAsync(root, ScanOptions.NoDependencyCheck);

        Assert.Contains(report.Findings, f => f.RuleId == "VC-PKG-001");
    }

    // ---- Found by unpacking and scanning real single-file applications ----

    /// <summary>
    /// The guarded ternary is the recommended fix for this rule, and the rule was reporting
    /// it. Telling a developer their correct fix is still a bug is worse than missing it.
    /// </summary>
    [Theory]
    [InlineData("Span<char> s = ((name.Length > 256) ? new char[name.Length] : stackalloc char[name.Length]);")]
    [InlineData("Span<byte> b = len <= 128 ? stackalloc byte[len] : new byte[len];")]
    [InlineData("Span<char> c = stackalloc char[Math.Min(input.Length, 256)];")]
    public void GuardedStackAlloc_IsNotFlagged(string line) =>
        Assert.DoesNotContain(
            RunRules(line, "Parser.cs"),
            f => f.RuleId == "VC-INPUT-001");

    [Fact]
    public void UnguardedStackAlloc_IsStillFlagged() =>
        Assert.Contains(
            RunRules("Span<char> s = stackalloc char[input.Length];", "Parser.cs"),
            f => f.RuleId == "VC-INPUT-001");

    /// <summary>
    /// The .NET runtimeconfig switch that disables BinaryFormatter was being reported as
    /// unsafe deserialisation. The mitigation is not the vulnerability.
    /// </summary>
    [Theory]
    [InlineData("""  "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization": false,""")]
    [InlineData("EnableUnsafeBinaryFormatterSerialization = false;")]
    public void DisablingSwitchForBinaryFormatter_IsNotFlagged(string line) =>
        Assert.DoesNotContain(
            RunRules(line, "app.runtimeconfig.json"),
            f => f.RuleId == "VC-CODE-004");

    [Fact]
    public void ActualBinaryFormatterUse_IsStillFlagged() =>
        Assert.Contains(
            RunRules("var f = new BinaryFormatter();", "Program.cs"),
            f => f.RuleId == "VC-CODE-004");

    /// <summary>
    /// PresentationUI was absent from the exclusion list, so a Microsoft help link inside it
    /// was reported as the application's own cleartext endpoint.
    /// </summary>
    [Theory]
    [InlineData("PresentationUI")]
    [InlineData("PresentationBuildTasks")]
    public void AllPresentationAssemblies_AreExcluded(string name) =>
        Assert.True(DotNetRecoveryBackend.IsFrameworkAssembly(name), $"{name} should be excluded");

    /// <summary>
    /// A legitimate application scored 38 and was labelled "Do not install" while the verdict
    /// itself correctly advised nothing of the sort. A low score means the application has
    /// problems; only a blocking rule means its user is at risk.
    /// </summary>
    [Fact]
    public void LowScoreAlone_DoesNotClaimTheUserIsAtRisk()
    {
        var verdict = ScoreCalculator.Calculate([
            Finding(Severity.Critical), Finding(Severity.High),
        ]);

        Assert.Equal(ScoreBand.CriticalIssues, verdict.Band);
        Assert.False(verdict.AdviseAgainstInstall);
        Assert.DoesNotContain("install", verdict.BandLabel, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A real application validated the scheme and host ten lines before launching, which is
    /// exactly the fix this rule recommends, and the rule reported it anyway because it only
    /// looked at the matched line.
    /// </summary>
    [Fact]
    public void ShellOpenGuardedByAnEarlierSchemeCheck_IsNotFlagged()
    {
        var guarded = """
            private void OpenUpdate()
            {
                if (_updateUrl == null) return;

                if (!Uri.TryCreate(_updateUrl, UriKind.Absolute, out var uri)
                    || uri.Scheme != Uri.UriSchemeHttps
                    || !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                try
                {
                    Process.Start(new ProcessStartInfo(_updateUrl) { UseShellExecute = true });
                }
                catch { }
            }
            """;

        Assert.DoesNotContain(RunRules(guarded, "MainViewModel.cs"), f => f.RuleId == "VC-INPUT-002");
    }

    [Fact]
    public void UnguardedShellOpen_IsStillFlagged()
    {
        var unguarded = """
            private void OpenUpdate()
            {
                Process.Start(new ProcessStartInfo(_updateUrl) { UseShellExecute = true });
            }
            """;

        Assert.Contains(RunRules(unguarded, "MainViewModel.cs"), f => f.RuleId == "VC-INPUT-002");
    }

    [Fact]
    public void NoBandLabel_ClaimsInstallSafety()
    {
        // No score range may imply a safety verdict in either direction; that judgement
        // belongs to the blocking rules alone.
        foreach (var band in Enum.GetValues<ScoreBand>())
        {
            var label = new Verdict
            {
                Score = 50,
                Band = band,
                AdviseAgainstInstall = false,
                Audience = Audience.Developer,
            }.BandLabel;

            Assert.DoesNotContain("install", label, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("safe", label, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- Found scanning a second batch of third-party applications --------

    /// <summary>
    /// A dependency-injection library's error message satisfied SELECT..FROM followed by a
    /// placeholder and was reported as SQL injection, twice, at Critical.
    /// </summary>
    [Theory]
    [InlineData("""Error = Of("Unable to select single public constructor from implementation type {0}:" + Environment.NewLine);""")]
    [InlineData("""throw new Exception("Cannot select handler from registry for {0}" + name);""")]
    [InlineData("""log.Warn("Failed to delete from cache: " + key);""")]
    public void EnglishSentencesWithSqlWords_AreNotFlagged(string line) =>
        Assert.DoesNotContain(RunRules(line, "Error.cs"), f => f.RuleId == "VC-CODE-001");

    /// <summary>
    /// Lower-case SQL is still SQL when it carries a real clause keyword, so the prose
    /// filter must not swallow it.
    /// </summary>
    [Theory]
    [InlineData("""var sql = "select id from users where name = '" + name + "'";""")]
    [InlineData("""cmd = "SELECT * FROM orders" + filter;""")]
    public void RealSqlInEitherCase_IsStillFlagged(string line) =>
        Assert.Contains(RunRules(line, "Repo.cs"), f => f.RuleId == "VC-CODE-001");

    /// <summary>
    /// A folder holding a .exe was classified as .NET regardless of what the binaries were,
    /// so a native application and a Python one both reported zero coverage with a
    /// .NET-flavoured explanation that told the user nothing.
    /// </summary>
    [Fact]
    public void FolderOfNativeBinaries_IsNotClassifiedAsDotNet()
    {
        var app = Path.Combine(_scratch, "native-app");
        Directory.CreateDirectory(app);
        File.Copy(
            Path.Combine(Environment.SystemDirectory, "kernel32.dll"),
            Path.Combine(app, "engine.dll"));

        Assert.Equal(ArtifactKind.NativeWindows, ArtifactDetector.Detect(app).Kind);
    }

    [Fact]
    public void FrozenPythonApplication_IsRecognised()
    {
        var app = Path.Combine(_scratch, "python-app");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "launcher.py"), "import sys");
        File.WriteAllBytes(Path.Combine(app, "_ssl.pyd"), [0x4D, 0x5A, 0x90, 0x00]);

        Assert.Equal(ArtifactKind.PythonBundle, ArtifactDetector.Detect(app).Kind);
    }

    /// <summary>
    /// Coverage was measuring recovery success on the files it could see rather than the
    /// share of the application examined, so thirteen readable files inside a 98 MB Python
    /// application reported 100% coverage and a near-perfect score.
    /// </summary>
    [Fact]
    public async Task CompiledPythonModules_CountAgainstCoverage()
    {
        var app = Path.Combine(_scratch, "mostly-compiled");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "main.py"), "import os");
        File.WriteAllBytes(Path.Combine(app, "_ssl.pyd"), [0x4D, 0x5A, 0x90, 0x00]);

        foreach (var i in Enumerable.Range(0, 200))
        {
            File.WriteAllBytes(Path.Combine(app, $"module{i}.pyc"), [0x6F, 0x0D, 0x0D, 0x0A]);
        }

        var report = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);

        Assert.Equal(ArtifactKind.PythonBundle, report.Kind);
        Assert.True(report.Coverage.Percent < 10, $"expected low coverage, got {report.Coverage.Percent}%");
        Assert.False(report.Verdict.HasMeaningfulScore);
        Assert.Contains(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("compiled Python", StringComparison.OrdinalIgnoreCase));
    }

    // ---- Found by running the application against a real folder -----------

    /// <summary>
    /// A leading U+FEFF makes JsonDocument.Parse throw, and Visual Studio and PowerShell
    /// both write UTF-8 BOMs by default. Left unhandled, a manifest saved by either tool was
    /// discarded and the application's whole dependency inventory silently went unchecked.
    /// </summary>
    [Fact]
    public async Task ManifestWithAUtf8Bom_IsStillParsed()
    {
        var app = Path.Combine(_scratch, "bom-manifest");
        Directory.CreateDirectory(app);

        File.WriteAllText(
            Path.Combine(app, "package-lock.json"),
            """{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}""",
            new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        var report = await new Scanner().ScanAsync(app, ScanOptions.NoDependencyCheck);

        Assert.DoesNotContain(
            report.Coverage.ChecksNotPossible,
            c => c.Contains("not valid JSON", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(new byte[] { 0xEF, 0xBB, 0xBF })]      // UTF-8
    [InlineData(new byte[] { 0xFF, 0xFE })]            // UTF-16 little endian
    [InlineData(new byte[] { 0xFE, 0xFF })]            // UTF-16 big endian
    public void ByteOrderMarks_AreHonouredAndStripped(byte[] bom)
    {
        var encoding = bom[0] switch
        {
            0xEF => (System.Text.Encoding)new System.Text.UTF8Encoding(false),
            0xFF => System.Text.Encoding.Unicode,
            _ => System.Text.Encoding.BigEndianUnicode,
        };

        byte[] bytes = [.. bom, .. encoding.GetBytes("""{"a":1}""")];

        Assert.Equal("""{"a":1}""", SafeArchive.DecodeText(bytes));
    }

    [Fact]
    public void ActualBinaryContent_IsStillRejected() =>
        Assert.Null(SafeArchive.DecodeText([0x89, 0x50, 0x4E, 0x47, 0x00, 0x01]));

    private static IReadOnlyList<Finding> RunRules(string content, string path = "src/app.js") =>
        new RuleEngine().Analyse([new RecoveredFile
        {
            RelativePath = path,
            Content = content,
            Language = RecoveredFile.LanguageOf(path),
        }]).Findings;
}
