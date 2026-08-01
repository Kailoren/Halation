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
        Category = FindingCategory.CodeSafety,
        Description = "test",
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
        Assert.Equal(ScoreBand.DoNotInstall, verdict.Band);
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

        var report = await new Scanner().ScanAsync(app);

        Assert.Contains(report.Findings, f => f.RuleId == "VC-PKG-001");
    }

    [Fact]
    public async Task ShippedEnvFile_IsReportedButExampleIsNot()
    {
        var app = Path.Combine(_scratch, "shipped-env");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, ".env"), "SECRET=abc");
        File.WriteAllText(Path.Combine(app, "index.js"), "run();");

        var withEnv = await new Scanner().ScanAsync(app);
        Assert.Contains(withEnv.Findings, f => f.RuleId == "VC-PKG-002");

        File.Delete(Path.Combine(app, ".env"));
        File.WriteAllText(Path.Combine(app, ".env.example"), "SECRET=");

        var withExample = await new Scanner().ScanAsync(app);
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

    private static IReadOnlyList<Finding> RunRules(string content, string path = "src/app.js") =>
        new RuleEngine().Analyse([new RecoveredFile
        {
            RelativePath = path,
            Content = content,
            Language = RecoveredFile.LanguageOf(path),
        }]).Findings;
}
