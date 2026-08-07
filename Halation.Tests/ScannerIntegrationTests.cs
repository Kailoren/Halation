using System.Text.Json;

using Halation.Core;
using Halation.Core.Model;
using Halation.Core.Reporting;

namespace Halation.Tests;

/// <summary>
/// End-to-end scans over a synthetic project carrying the failures AI code generators
/// actually produce. These exercise detection, recovery, rules, scoring, and reporting
/// together, which is where integration mistakes show up that unit tests pass through.
/// </summary>
public class ScannerIntegrationTests : IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("vibecheck-e2e-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException) { }

        GC.SuppressFinalize(this);
    }

    /// <summary>Writes a project shaped like a typical AI-generated web application.</summary>
    private string BuildVulnerableProject()
    {
        var root = Path.Combine(_scratch, "my-saas-app");
        Directory.CreateDirectory(Path.Combine(root, "src"));
        Directory.CreateDirectory(Path.Combine(root, "server"));

        File.WriteAllText(Path.Combine(root, "package.json"), """
            { "name": "my-saas-app", "version": "1.0.0", "main": "electron.js" }
            """);

        File.WriteAllText(Path.Combine(root, ".env"), """
            DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/app
            STRIPE_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dcabcd
            """);

        File.WriteAllText(Path.Combine(root, "src", "supabase.js"), $$"""
            import { createClient } from '@supabase/supabase-js';

            // Works locally, ship it
            export const supabase = createClient(
              'https://abcdefgh.supabase.co',
              '{{Jwt("service_role")}}'
            );
            """);

        File.WriteAllText(Path.Combine(root, "server", "api.js"), """
            const express = require('express');
            const app = express();

            app.use(cors({ origin: '*', credentials: true }));

            app.get('/user/:id', async (req, res) => {
              const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
              res.json(rows);
            });

            const agent = new https.Agent({ rejectUnauthorized: false });

            app.listen(8080, '0.0.0.0');
            """);

        File.WriteAllText(Path.Combine(root, "electron.js"), """
            const { BrowserWindow } = require('electron');

            function createWindow() {
              const win = new BrowserWindow({
                webPreferences: { nodeIntegration: true, contextIsolation: false }
              });
              win.loadURL('http://updates.example.com/app');
            }
            """);

        // A correctly written file, to confirm the scanner does not simply flag everything.
        File.WriteAllText(Path.Combine(root, "src", "safe.js"), """
            const apiKey = process.env.API_KEY;

            export async function getUser(id) {
              return db.query('SELECT * FROM users WHERE id = $1', [id]);
            }
            """);

        return root;
    }

    [Fact]
    public async Task VulnerableProject_ProducesCriticalFindingsAndLowScore()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        Assert.Equal(ArtifactKind.SourceTree, report.Kind);
        Assert.NotEmpty(report.Findings);

        // The Supabase service_role key alone should force the red band.
        Assert.True(report.Verdict.Score <= 39, $"expected <= 39, got {report.Verdict.Score}");
        Assert.Equal(ScoreBand.CriticalIssues, report.Verdict.Band);
        Assert.True(report.CountOf(Severity.Critical) > 0);
    }

    [Fact]
    public async Task VulnerableProject_FindsEachPlantedIssue()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);
        var fired = report.Findings.Select(f => f.RuleId).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("VC-SEC-011", fired);  // Supabase service_role key
        Assert.Contains("VC-SEC-003", fired);  // live Stripe key
        Assert.Contains("VC-CFG-004", fired);  // CORS wildcard with credentials
        Assert.Contains("VC-CFG-005", fired);  // TLS verification disabled
        Assert.Contains("VC-CFG-008", fired);  // binds to all interfaces
        Assert.Contains("VC-CFG-002", fired);  // Electron nodeIntegration
        Assert.Contains("VC-CODE-001", fired); // SQL string interpolation
    }

    /// <summary>
    /// A scanner that flags correct code alongside incorrect code teaches users to ignore it.
    /// </summary>
    [Fact]
    public async Task CorrectlyWrittenFile_ProducesNoFindings()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        Assert.DoesNotContain(
            report.Findings,
            f => f.FilePath?.EndsWith("safe.js", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task CleanProject_ScoresWellAndAdvisesNothing()
    {
        var root = Path.Combine(_scratch, "clean-app");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "index.js"), """
            const key = process.env.API_KEY;

            export async function getUser(db, id) {
              return db.query('SELECT * FROM users WHERE id = $1', [id]);
            }
            """);

        var report = await new Scanner().ScanAsync(root, ScanOptions.NoDependencyCheck);

        Assert.Empty(report.Findings);
        Assert.Equal(100, report.Verdict.Score);
        Assert.False(report.Verdict.AdviseAgainstInstall);
    }

    [Fact]
    public async Task MaliciousApplication_AdvisesAgainstInstalling()
    {
        var root = Path.Combine(_scratch, "free-game-cheat");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "index.js"), """
            const appData = process.env.LOCALAPPDATA;
            const creds = path.join(appData, 'Google/Chrome/User Data/Default/Login Data');
            const wallet = path.join(home, 'Exodus/exodus.wallet');
            upload(read(creds), read(wallet));
            """);

        var report = await new Scanner().ScanAsync(root, ScanOptions.NoDependencyCheck);

        Assert.True(report.Verdict.AdviseAgainstInstall);
        Assert.NotEmpty(report.Verdict.BlockingReasons);
        Assert.Equal(ScoreBand.CriticalIssues, report.Verdict.Band);
    }

    /// <summary>
    /// The promise the obfuscation change was made for, checked where a reader would meet it:
    /// not in the coverage figure but in the verdict. A scrambled application decompiles into
    /// thousands of files nothing can read, matches no rules because there is nothing legible to
    /// match, and used to come out the far end with a high score and a short findings list. It
    /// now gets no number at all, which is the honest answer, and a band that is grey rather
    /// than green.
    /// </summary>
    [Fact]
    public async Task ObfuscatedApplication_GetsNoScoreRatherThanAGoodOne()
    {
        var path = ObfuscatedAssemblyBuilder.WriteTemp();

        try
        {
            var report = await new Scanner().ScanAsync(path, ScanOptions.NoDependencyCheck);

            Assert.False(report.Verdict.HasMeaningfulScore);
            Assert.Equal(ScoreBand.InsufficientCoverage, report.Verdict.Band);

            // Not a failing grade either. It could not be read, and that is all the report says.
            Assert.False(report.Verdict.AdviseAgainstInstall);

            // The reason is in the report rather than left to be inferred from a missing number.
            Assert.Contains(report.Findings, f => f.RuleId == "VC-BIN-002");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task NativeBinary_ScoresButReportsZeroCoverage()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var report = await new Scanner().ScanAsync(kernel32, ScanOptions.NoDependencyCheck);

        Assert.Equal(ArtifactKind.NativeWindows, report.Kind);
        Assert.Equal(0, report.Coverage.Percent);
        Assert.NotEmpty(report.Coverage.ChecksNotPossible);
    }

    [Fact]
    public async Task Report_CarriesReproducibleIdentity()
    {
        var project = BuildVulnerableProject();

        var first = await new Scanner().ScanAsync(project, ScanOptions.NoDependencyCheck);
        var second = await new Scanner().ScanAsync(project, ScanOptions.NoDependencyCheck);

        Assert.Equal(first.Sha256, second.Sha256);
        Assert.Equal(first.Verdict.Score, second.Verdict.Score);
        Assert.Equal(first.Findings.Count, second.Findings.Count);
    }

    [Fact]
    public async Task Cancellation_IsHonoured()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck, cancellationToken: cancelled.Token));
    }

    /// <summary>
    /// Renders a full report and leaves it on disk for manual review, while asserting the
    /// parts that must always be present.
    /// </summary>
    [Fact]
    public async Task MarkdownReport_IsCompleteAndCarriesItsCaveats()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);
        var markdown = MarkdownReportWriter.Write(report);

        File.WriteAllText(
            Path.Combine(Path.GetTempPath(), "vibecheck-sample-report.md"),
            markdown);

        Assert.Contains("# VibeCheck report", markdown, StringComparison.Ordinal);
        Assert.Contains("/100", markdown, StringComparison.Ordinal);
        Assert.Contains("## Coverage", markdown, StringComparison.Ordinal);

        // The honesty caveats are not optional furniture; assert they survive.
        Assert.Contains("cannot show that none are", markdown, StringComparison.Ordinal);
        Assert.Contains("were not performed", markdown, StringComparison.Ordinal);

        // No live credential may appear in an exported report.
        Assert.DoesNotContain("sk_live_4eC39HqLyjWDarjtT1zdp7dcabcd", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// The deep pass spends the reader's own money. The report is the only place they learn
    /// how much before their API console catches up a day later, so the figure has to reach it.
    /// </summary>
    [Fact]
    public async Task MarkdownReport_StatesWhatTheDeepPassCost()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        var markdown = MarkdownReportWriter.Write(report with
        {
            DeepPassRan = true,
            DeepPassBackend = "the Anthropic API (claude-opus-5)",
            DeepPassCost = 0.42m,
        });

        Assert.Contains("US$0.42", markdown, StringComparison.Ordinal);
        Assert.Contains("on your API key", markdown, StringComparison.Ordinal);
    }

    /// <summary>A third of a cent is cheap, not free; "US$0.00" would say the wrong one.</summary>
    [Fact]
    public async Task MarkdownReport_DoesNotRoundASmallDeepPassBillDownToNothing()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        var markdown = MarkdownReportWriter.Write(report with
        {
            DeepPassRan = true,
            DeepPassBackend = "the Anthropic API (claude-opus-5)",
            DeepPassCost = 0.003m,
        });

        Assert.Contains("under US$0.01", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("US$0.00", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// A subscription-backed pass bills nothing. The CLI still reports what the same request
    /// would have cost through the API, and printing that would tell somebody whose card was
    /// never touched that they had been charged.
    /// </summary>
    [Fact]
    public async Task MarkdownReport_DoesNotClaimASubscriptionRunCostMoney()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        var markdown = MarkdownReportWriter.Write(report with
        {
            DeepPassRan = true,
            DeepPassBackend = "the Claude Code CLI bundled with the Claude desktop app (2.1.219)",
            DeepPassCost = null,
        });

        Assert.DoesNotContain("US$", markdown, StringComparison.Ordinal);
        Assert.Contains("quota rather than money", markdown, StringComparison.Ordinal);

        // Specifically the billing sentence. A bare "API key" search also matches the name of
        // any rule that looks for one, which says nothing about what the scan charged.
        Assert.DoesNotContain("on your API key", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// A deep pass that was asked for and could not run must not read as one that ran and cost
    /// nothing, which is what a bare "US$0.00" would say.
    /// </summary>
    [Fact]
    public async Task MarkdownReport_SaysWhenTheDeepPassDidNotRunAtAll()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        var markdown = MarkdownReportWriter.Write(report with
        {
            DeepPassRan = true,
            DeepPassBackend = null,
            DeepPassCost = null,
        });

        Assert.Contains("did not run", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("US$0.00", markdown, StringComparison.Ordinal);
    }

    /// <summary>The report names what answered, so two scans that disagree can be told apart.</summary>
    [Fact]
    public async Task MarkdownReport_NamesTheBackendThatAnsweredTheDeepPass()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject(), ScanOptions.NoDependencyCheck);

        var markdown = MarkdownReportWriter.Write(report with
        {
            DeepPassRan = true,
            DeepPassBackend = "the Anthropic API (claude-opus-5)",
            DeepPassCost = 0.42m,
        });

        Assert.Contains("the Anthropic API (claude-opus-5)", markdown, StringComparison.Ordinal);
    }

    private static string Jwt(string role)
    {
        static string Segment(object value) =>
            Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return $"{Segment(new { alg = "HS256", typ = "JWT" })}."
               + $"{Segment(new { iss = "supabase", role, iat = 1700000000, exp = 1900000000 })}."
               + "tG7Yk2Qp9Lm4Xv8Nc3Bz1Rw6Ht5Ja0Sd";
    }
}
