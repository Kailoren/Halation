using Halation.Core;
using Halation.Core.DeepPass;
using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Reporting;

namespace Halation.Tests;

/// <summary>
/// What the report is allowed to say about the deep pass.
/// </summary>
/// <remarks>
/// Written after a measured run against a real Electron application, where the deep pass failed
/// on every one of five files with an expired sign-in and the report said the files "were also
/// read a second time by the AI", named the CLI as having answered, and claimed its findings were
/// included, with zero tokens spent. Every sentence about the pass now comes from what happened,
/// and these are the states it has to tell apart.
/// </remarks>
public class DeepPassOutcomeTests
{
    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    /// <summary>Two files that both qualify for the pass, so a partial result is possible.</summary>
    private static IReadOnlyList<RecoveredFile> Files =>
    [
        File("client.js", "const body = await fetch(url);"),
        File("reader.js", "const text = require('fs').readFileSync(path);"),
    ];

    /// <summary>A backend that answers however the test needs it to.</summary>
    private sealed class Scripted(params FileReview[] replies) : IDeepPassBackend
    {
        private int _next;

        public string Description => "a stand-in backend";

        public bool BillsTheReader => false;

        public bool SpendsSubscription { get; init; }

        public int Calls { get; private set; }

        public decimal? PriceOf(TokenUsage usage) => null;

        public Task<FileReview> ReviewAsync(DeepPassChunk chunk, CancellationToken ct = default)
        {
            Calls++;

            var reply = replies[Math.Min(_next, replies.Length - 1)];
            _next++;

            return Task.FromResult(reply);
        }

        public void Dispose()
        {
        }
    }

    private static Task<DeepPassResult> RunAsync(IDeepPassBackend backend) =>
        DeepPassRunner.RunAsync(
            Files,
            [],
            new ScanOptions { DeepPassApiKey = "sk-ant-test" },
            backend);

    private static FileReview Reviewed => new();

    private static FileReview Failed(bool stops = false) => new()
    {
        Outcome = ReviewOutcome.Failed,
        StopsPass = stops,
        Limitation = "it failed",
    };

    // ---- The outcome itself -------------------------------------------------

    [Fact]
    public async Task A_pass_where_every_request_failed_is_not_reported_as_one_that_ran()
    {
        var result = await RunAsync(new Scripted(Failed()));

        Assert.Equal(DeepPassOutcome.Failed, result.Outcome);
        Assert.Equal(0, result.FilesReviewed);
        Assert.Equal(2, result.FilesFailed);
        Assert.Equal(0, result.CodeReviewedPercent);

        var said = string.Join(" ", result.Limitations);

        Assert.Contains("did not review anything", said, StringComparison.Ordinal);
        Assert.DoesNotContain("read a second time", said, StringComparison.Ordinal);
        Assert.DoesNotContain("was answered by", said, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pass_that_read_everything_says_so_and_states_its_own_coverage()
    {
        var result = await RunAsync(new Scripted(Reviewed));

        Assert.Equal(DeepPassOutcome.Reviewed, result.Outcome);
        Assert.Equal(2, result.FilesReviewed);
        Assert.Equal(100, result.CodeReviewedPercent);

        var said = string.Join(" ", result.Limitations);

        Assert.Contains("was answered by", said, StringComparison.Ordinal);
        Assert.Contains("read 100% of this application", said, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pass_that_read_some_of_it_is_reported_as_partial()
    {
        var result = await RunAsync(new Scripted(Reviewed, Failed()));

        Assert.Equal(DeepPassOutcome.PartlyReviewed, result.Outcome);
        Assert.Equal(1, result.FilesReviewed);
        Assert.Equal(1, result.FilesFailed);

        // Measured against the whole application, not against what was sent, so half of it
        // cannot come out as complete coverage.
        Assert.InRange(result.CodeReviewedPercent ?? 0, 1, 99);
    }

    // ---- Stopping -----------------------------------------------------------

    /// <summary>
    /// The sign-in gate reads <c>auth status</c>, which answers without making a request and
    /// therefore cannot see an expired session. The first real request can, and the rest of the
    /// pass is not spent proving it again.
    /// </summary>
    [Fact]
    public async Task A_failure_that_will_repeat_stops_the_pass_instead_of_spending_every_file()
    {
        var backend = new Scripted(Failed(stops: true));

        var result = await RunAsync(backend);

        Assert.Equal(1, backend.Calls);
        Assert.Equal(DeepPassOutcome.Failed, result.Outcome);
        Assert.Equal(1, result.FilesNotAttempted);
    }

    // ---- What the exports then say -----------------------------------------

    private static ScanReport Report(DeepPassOutcome outcome) => new()
    {
        ArtifactName = "app.zip",
        Kind = ArtifactKind.ElectronApp,
        ArtifactBytes = 1024,
        Sha256 = new string('a', 64),
        ScannedAt = DateTimeOffset.Now,
        Verdict = Halation.Core.Scoring.ScoreCalculator.Calculate([], 100, Audience.Developer, []),
        Coverage = new CoverageReport { Percent = 100, Basis = "read it all" },
        Findings = [],
        CategoryScores = new Dictionary<FindingCategory, int>(),
        VulnerabilityData = Halation.Core.Dependencies.VulnerabilityDataProvenance.Unavailable,
        Effort = new ScanEffort
        {
            RecoveryMethod = "reading the source directly",
            FilesRecovered = 2,
            BytesRecovered = 100,
            ChecksRun = 40,
            FilesChecked = 2,
            PackagesResolved = 0,
            PackagesChecked = 0,
            VulnerabilityData = Halation.Core.Dependencies.VulnerabilityDataProvenance.Unavailable,
        },
        ScannerVersion = "0.1.6-beta",
        DeepPassState = outcome,
        DeepPassBackend = outcome == DeepPassOutcome.NotRun ? null : "a stand-in backend",
        DeepPassFilesSelected = 2,
        DeepPassFilesReviewed = outcome == DeepPassOutcome.Reviewed ? 2 : 0,
        DeepPassCodeReviewedPercent = outcome == DeepPassOutcome.Reviewed ? 100 : 0,
        DeepPassTokens = outcome is DeepPassOutcome.NotRequested or DeepPassOutcome.NotRun
            ? null
            : 0,
        DeepPassSpentSubscription = outcome != DeepPassOutcome.NotRequested,
    };

    [Fact]
    public void The_footer_does_not_claim_findings_from_a_pass_that_failed()
    {
        var markdown = MarkdownReportWriter.Write(Report(DeepPassOutcome.Failed));

        Assert.DoesNotContain("Includes findings from the optional AI deep pass", markdown,
            StringComparison.Ordinal);

        Assert.Contains("every request failed", markdown, StringComparison.Ordinal);

        // And no claim about spending, because nothing was spent. This is the sentence that
        // told a reader their subscription quota had gone on a pass that never read a line.
        Assert.DoesNotContain("spent your Claude subscription", markdown, StringComparison.Ordinal);
        Assert.Contains("No quota or money was spent", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void The_footer_says_nothing_about_a_pass_nobody_asked_for()
    {
        var markdown = MarkdownReportWriter.Write(Report(DeepPassOutcome.NotRequested));

        Assert.DoesNotContain("deep pass", markdown, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_result_carries_the_caveat_where_the_score_is()
    {
        Assert.Null(Report(DeepPassOutcome.NotRequested).DeepPassCaveat);
        Assert.Null(Report(DeepPassOutcome.Reviewed).DeepPassCaveat);

        foreach (var outcome in new[]
                 {
                     DeepPassOutcome.NotRun,
                     DeepPassOutcome.Failed,
                     DeepPassOutcome.PartlyReviewed,
                 })
        {
            var report = Report(outcome);

            Assert.NotNull(report.DeepPassCaveat);
            Assert.Contains(
                report.DeepPassCaveat!,
                MarkdownReportWriter.Write(report),
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_json_export_states_the_outcome_and_the_coverage_the_ai_reached()
    {
        var json = System.Text.Json.JsonDocument.Parse(
            JsonReportWriter.Write(Report(DeepPassOutcome.Failed)));

        var pass = json.RootElement.GetProperty("deepPass");

        Assert.Equal("Failed", pass.GetProperty("outcome").GetString());
        Assert.Equal(0, pass.GetProperty("filesReviewed").GetInt32());
        Assert.Equal(0, pass.GetProperty("codeReviewedPercent").GetInt32());

        // Absent when nobody asked, so a consumer can tell that from a pass that read nothing.
        Assert.False(
            System.Text.Json.JsonDocument
                .Parse(JsonReportWriter.Write(Report(DeepPassOutcome.NotRequested)))
                .RootElement.TryGetProperty("deepPass", out _));
    }

    /// <summary>
    /// The sharing copy is the same writer over a stripped report, so it inherits the wording.
    /// Worth pinning: it is the copy that gets posted in public.
    /// </summary>
    [Fact]
    public void The_sharing_copy_reports_the_same_outcome()
    {
        var shared = MarkdownReportWriter.Write(Report(DeepPassOutcome.Failed).ForSharing());

        Assert.Contains("every request failed", shared, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Includes findings from the optional AI deep pass", shared, StringComparison.Ordinal);
    }
}
