using System.Text.Json;

using VibeCheck.Core;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;

namespace VibeCheck.Tests;

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
        var report = await new Scanner().ScanAsync(BuildVulnerableProject());

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
        var report = await new Scanner().ScanAsync(BuildVulnerableProject());
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
        var report = await new Scanner().ScanAsync(BuildVulnerableProject());

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

        var report = await new Scanner().ScanAsync(root);

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

        var report = await new Scanner().ScanAsync(root);

        Assert.True(report.Verdict.AdviseAgainstInstall);
        Assert.NotEmpty(report.Verdict.BlockingReasons);
        Assert.Equal(ScoreBand.CriticalIssues, report.Verdict.Band);
    }

    [Fact]
    public async Task NativeBinary_ScoresButReportsZeroCoverage()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var report = await new Scanner().ScanAsync(kernel32);

        Assert.Equal(ArtifactKind.NativeWindows, report.Kind);
        Assert.Equal(0, report.Coverage.Percent);
        Assert.NotEmpty(report.Coverage.ChecksNotPossible);
    }

    [Fact]
    public async Task Report_CarriesReproducibleIdentity()
    {
        var project = BuildVulnerableProject();

        var first = await new Scanner().ScanAsync(project);
        var second = await new Scanner().ScanAsync(project);

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
            () => new Scanner().ScanAsync(BuildVulnerableProject(), cancellationToken: cancelled.Token));
    }

    /// <summary>
    /// Renders a full report and leaves it on disk for manual review, while asserting the
    /// parts that must always be present.
    /// </summary>
    [Fact]
    public async Task MarkdownReport_IsCompleteAndCarriesItsCaveats()
    {
        var report = await new Scanner().ScanAsync(BuildVulnerableProject());
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
