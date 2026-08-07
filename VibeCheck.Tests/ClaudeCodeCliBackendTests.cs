using System.Text.Json;

using VibeCheck.Core;
using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

/// <summary>
/// This backend hands source recovered from untrusted software to an agent that can act on the
/// machine, which is only safe because of the flags it passes and the audience it is restricted
/// to. Both are asserted here rather than left to review, because a regression in either turns
/// a security scanner into the delivery mechanism for the thing it was asked to look for.
/// </summary>
public class ClaudeCodeCliBackendTests
{
    private static ClaudeCodeCli Cli => new()
    {
        Path = Path.Combine(Path.GetTempPath(), "claude.exe"),
        Source = ClaudeCodeCliSource.PackagedDesktopApp,
        Version = new Version(2, 1, 219),
    };

    private static TriagedFile Triaged(string path = "handler.js") => new()
    {
        File = new RecoveredFile
        {
            RelativePath = path,
            Content = "app.get('/run', (q) => exec(q.cmd));",
            Language = RecoveredFile.LanguageOf(path),
        },
        Reason = "handles untrusted input",
        KnownFindings = [],
    };

    /// <summary>A result envelope in the shape the CLI actually produces.</summary>
    private static string Envelope(
        string? structuredOutput = null,
        bool isError = false,
        string stopReason = "tool_use",
        string? result = null,
        string? modelUsage = null,
        string permissionDenials = "[]") =>
        $$"""
        {
          "is_error": {{(isError ? "true" : "false")}},
          "stop_reason": "{{stopReason}}",
          "num_turns": 2,
          "total_cost_usd": 0.0085,
          "usage": {
            "input_tokens": 877,
            "output_tokens": 353,
            "cache_creation_input_tokens": 12,
            "cache_read_input_tokens": 3289
          },
          "modelUsage": {{modelUsage ?? """{"claude-opus-5": {"canonicalModel": "claude-opus-5"}}"""}},
          "permission_denials": {{permissionDenials}},
          "terminal_reason": "completed",
          "subtype": "success",
          {{(structuredOutput is null ? "" : $"\"structured_output\": {structuredOutput},")}}
          "result": {{JsonSerializer.Serialize(result ?? structuredOutput ?? "")}}
        }
        """;

    private const string OneFinding =
        """
        {"findings": [{
          "title": "Command injection in the run endpoint",
          "severity": "critical",
          "user_severity": "high",
          "user_impact": "Anyone who can reach this could run programs on the machine.",
          "file": "handler.js",
          "evidence": "exec(q.cmd)",
          "reachability": "Reached directly from an HTTP query parameter.",
          "why_rules_miss_it": "The sink is reached through an alias a pattern would not follow.",
          "remediation": "Do not pass request input to a shell.",
          "confidence": "high"
        }]}
        """;

    // ---- The security boundary ---------------------------------------------

    /// <summary>
    /// The flag that makes this defensible. Claude Code is an agent with shell and filesystem
    /// access; without this the reviewed code can talk to something that can act.
    /// </summary>
    [Fact]
    public void Disables_every_tool()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var arguments = backend.Arguments();
        var index = arguments.ToList().IndexOf("--tools");

        Assert.True(index >= 0, "the tool list must be set explicitly, never left to default");
        Assert.Equal(string.Empty, arguments[index + 1]);
    }

    /// <summary>
    /// The other half of the same boundary, and the half that was missing.
    /// </summary>
    /// <remarks>
    /// <c>--tools ""</c> disables the built-in set, in the CLI's own words, and an MCP server the
    /// reader has configured is not in that set. Since the model is reading an application nobody
    /// trusts, a tool left reachable is a way for the scanned code to act on the machine of the
    /// person scanning it.
    /// </remarks>
    [Fact]
    public void Leaves_no_mcp_server_reachable()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var arguments = backend.Arguments();

        Assert.Contains("--strict-mcp-config", arguments);

        // And nothing may hand it a configuration to be strict about.
        Assert.DoesNotContain("--mcp-config", arguments);

        var denied = arguments.ToList().IndexOf("--disallowed-tools");
        Assert.True(denied >= 0, "the backstop against MCP tools must be set");
        Assert.Equal("mcp__*", arguments[denied + 1]);
    }

    /// <summary>The value after <c>--tools</c> must be the empty string and nothing else.</summary>
    [Fact]
    public void Never_names_a_tool_it_would_allow()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.DoesNotContain("--allowed-tools", backend.Arguments());
        Assert.DoesNotContain("--allowedTools", backend.Arguments());
        Assert.DoesNotContain("default", backend.Arguments());
    }

    /// <summary>
    /// Nothing may weaken permissions. These flags exist for sandboxes with no network; the
    /// machine running a scan is neither.
    /// </summary>
    [Fact]
    public void Never_bypasses_permission_checks()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.DoesNotContain("--dangerously-skip-permissions", backend.Arguments());
        Assert.DoesNotContain("--allow-dangerously-skip-permissions", backend.Arguments());
        Assert.DoesNotContain("--permission-mode", backend.Arguments());
        Assert.DoesNotContain("--add-dir", backend.Arguments());
    }

    /// <summary>
    /// Customisations belong to the reader's own workflow and were not chosen when they asked
    /// for a scan. A hook or MCP server firing during a review is code the scan invited to run.
    /// </summary>
    [Fact]
    public void Disables_customisations_and_session_persistence()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.Contains("--safe-mode", backend.Arguments());
        Assert.Contains("--no-session-persistence", backend.Arguments());
        Assert.Contains("-p", backend.Arguments());
    }

    /// <summary>
    /// The working directory is created empty, so there is nothing local for the agent to find
    /// even if one of the flags above stops meaning what it means.
    /// </summary>
    [Fact]
    public void Works_in_an_empty_directory_and_removes_it_afterwards()
    {
        string directory;

        using (var backend = new ClaudeCodeCliBackend(Cli))
        {
            directory = backend.WorkingDirectory;

            Assert.True(Directory.Exists(directory));
            Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
        }

        Assert.False(Directory.Exists(directory));
    }

    /// <summary>Two scans running at once must not share a directory.</summary>
    [Fact]
    public void Gives_each_backend_its_own_directory()
    {
        using var first = new ClaudeCodeCliBackend(Cli);
        using var second = new ClaudeCodeCliBackend(Cli);

        Assert.NotEqual(first.WorkingDirectory, second.WorkingDirectory);
    }

    // ---- Staying comparable with the API backend ---------------------------

    /// <summary>
    /// Both backends must ask the same question. Appending would leave a coding agent's own
    /// instructions in front of the review prompt and the answer would no longer compare.
    /// </summary>
    [Fact]
    public void Sends_the_shared_system_prompt_verbatim_and_does_not_append_to_a_default()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.Contains("--system-prompt", backend.Arguments());
        Assert.DoesNotContain("--append-system-prompt", backend.Arguments());
        Assert.Contains(DeepPassPrompt.SystemPrompt, backend.Arguments());
    }

    /// <summary>The same schema object the API backend constrains against.</summary>
    [Fact]
    public void Constrains_output_with_the_shared_schema()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var arguments = backend.Arguments();
        var index = arguments.ToList().IndexOf("--json-schema");

        Assert.True(index >= 0);
        Assert.Equal(
            JsonSerializer.Serialize(DeepPassPrompt.FindingSchema),
            arguments[index + 1]);
    }

    [Fact]
    public void Requests_the_same_model_as_the_api_backend_by_default()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var arguments = backend.Arguments();
        var index = arguments.ToList().IndexOf("--model");

        Assert.True(index >= 0);
        Assert.Equal("claude-opus-5", arguments[index + 1]);
    }

    // ---- What it bills -----------------------------------------------------

    /// <summary>
    /// The run spends subscription quota, not money. The CLI still reports a dollar figure,
    /// and treating that as a bill would be a false statement in the report.
    /// </summary>
    [Fact]
    public void Does_not_bill_the_reader()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.False(backend.BillsTheReader);
    }

    [Fact]
    public void Names_itself_and_the_model_it_ran()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        Assert.Contains("Claude desktop app", backend.Description, StringComparison.Ordinal);
        Assert.Contains("claude-opus-5", backend.Description, StringComparison.Ordinal);
    }

    // ---- Reading the result envelope ---------------------------------------

    /// <summary>
    /// Structured output arrives as a forced tool call, so a schema-constrained run reports
    /// stop_reason "tool_use". Treating that as the agent reaching for a tool would discard
    /// every successful review.
    /// </summary>
    [Fact]
    public void Reads_findings_from_a_successful_structured_run()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(structuredOutput: OneFinding), Triaged());

        var finding = Assert.Single(review.Findings);
        Assert.Equal("Command injection in the run endpoint", finding.Title);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Null(review.Limitation);
    }

    /// <summary>Deep pass findings can never drive the strongest claim in a report.</summary>
    [Fact]
    public void Marks_its_findings_as_assisted()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(structuredOutput: OneFinding), Triaged());

        Assert.Equal(FindingSource.Assisted, Assert.Single(review.Findings).Source);
    }

    [Fact]
    public void Falls_back_to_the_result_text_when_there_is_no_structured_output()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(result: OneFinding), Triaged());

        Assert.Single(review.Findings);
    }

    [Fact]
    public void Counts_the_tokens_the_run_used_including_cached_ones()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(structuredOutput: OneFinding), Triaged());

        Assert.Equal(877, review.Usage.Input);
        Assert.Equal(353, review.Usage.Output);
        Assert.Equal(12, review.Usage.CacheWrite);
        Assert.Equal(3_289, review.Usage.CacheRead);
    }

    /// <summary>
    /// A failed run still arrives with a success-shaped envelope, so branching on "subtype"
    /// would read a failure as a clean review that found nothing.
    /// </summary>
    [Fact]
    public void Treats_an_error_envelope_as_a_failure_despite_its_success_subtype()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(isError: true, result: "Invalid API key"), Triaged());

        Assert.Empty(review.Findings);
        Assert.NotNull(review.Limitation);
        Assert.Contains("handler.js", review.Limitation, StringComparison.Ordinal);
    }

    /// <summary>
    /// The difference from the API backend that a reader has to be told about. There, a policy
    /// decline is re-served by a substitute model inside the same call. Here nothing retries,
    /// so the file is simply not covered.
    /// </summary>
    [Fact]
    public void Says_that_a_declined_file_was_not_reviewed_at_all()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(stopReason: "refusal"), Triaged());

        Assert.Empty(review.Findings);
        Assert.NotNull(review.Limitation);
        Assert.Contains("declined", review.Limitation, StringComparison.Ordinal);
        Assert.Contains("not reviewed at all", review.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void Says_when_a_review_was_cut_off_before_it_finished()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(Envelope(stopReason: "max_tokens"), Triaged());

        Assert.NotNull(review.Limitation);
        Assert.Contains("cut off", review.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void Treats_a_reply_that_is_not_json_as_a_failure()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult("command not found", Triaged());

        Assert.Empty(review.Findings);
        Assert.NotNull(review.Limitation);
    }

    // ---- Confidence --------------------------------------------------------

    private static string Finding(string title, string confidence) =>
        $$"""
        {
          "title": "{{title}}", "severity": "high", "user_severity": "medium",
          "user_impact": "x", "file": "handler.js", "evidence": "exec(q.cmd)",
          "reachability": "x", "why_rules_miss_it": "x", "remediation": "x",
          "confidence": "{{confidence}}"
        }
        """;

    /// <summary>
    /// A finding the model did not believe is worth less than the trust it costs to print it
    /// with a warning attached, so it is dropped rather than hedged.
    /// </summary>
    [Fact]
    public void Drops_findings_the_model_marked_low_confidence()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(structuredOutput: $$"""
                {"findings": [{{Finding("kept", "high")}}, {{Finding("dropped", "low")}}]}
                """),
            Triaged());

        var kept = Assert.Single(review.Findings);
        Assert.Equal("kept", kept.Title);
        Assert.Equal(1, review.LowConfidenceDiscarded);
    }

    [Fact]
    public void Keeps_medium_confidence_findings()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(structuredOutput: $$"""{"findings": [{{Finding("kept", "medium")}}]}"""),
            Triaged());

        Assert.Single(review.Findings);
        Assert.Equal(0, review.LowConfidenceDiscarded);
    }

    /// <summary>
    /// Absence of a confidence claim is not a confession of doubt. Dropping on a field the
    /// model failed to fill would shrink coverage for a formatting reason.
    /// </summary>
    [Fact]
    public void Keeps_a_finding_that_states_no_confidence_at_all()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(structuredOutput: """
                {"findings": [{"title": "no confidence field", "severity": "high",
                 "user_severity": "low", "user_impact": "x", "file": "handler.js",
                 "evidence": "x", "reachability": "x", "why_rules_miss_it": "x",
                 "remediation": "x"}]}
                """),
            Triaged());

        Assert.Single(review.Findings);
        Assert.Equal(0, review.LowConfidenceDiscarded);
    }

    /// <summary>
    /// A file whose findings were all dropped must not look like a file with nothing to say.
    /// </summary>
    [Fact]
    public void Counts_what_it_dropped_rather_than_discarding_it_silently()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(structuredOutput: $$"""
                {"findings": [{{Finding("a", "low")}}, {{Finding("b", "low")}}]}
                """),
            Triaged());

        Assert.Empty(review.Findings);
        Assert.Equal(2, review.LowConfidenceDiscarded);
    }

    // ---- Which model answered ----------------------------------------------

    /// <summary>
    /// A run legitimately involves more than one model, because the CLI makes small auxiliary
    /// calls of its own. Reading that as a substitution would report every single review as
    /// having been answered by something other than what was asked for.
    /// </summary>
    [Fact]
    public void Does_not_mistake_the_clis_own_auxiliary_call_for_a_substitution()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(
                structuredOutput: OneFinding,
                modelUsage: """
                {
                  "claude-haiku-4-5-20251001": {"canonicalModel": "claude-haiku-4-5"},
                  "claude-opus-5": {"canonicalModel": "claude-opus-5"}
                }
                """),
            Triaged());

        Assert.False(review.ServedByFallback);
    }

    /// <summary>
    /// When the requested model is absent from the accounting, something else answered, and a
    /// reader comparing two reports is owed that.
    /// </summary>
    [Fact]
    public void Reports_when_a_different_model_answered()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(
                structuredOutput: OneFinding,
                modelUsage: """{"claude-sonnet-5": {"canonicalModel": "claude-sonnet-5"}}"""),
            Triaged());

        Assert.True(review.ServedByFallback);
    }

    // ---- Signals from the reviewed code ------------------------------------

    /// <summary>
    /// With no tools available there is nothing to reach for, so an attempt says something
    /// about the text that was fed in rather than about the agent.
    /// </summary>
    [Fact]
    public void Reports_an_attempt_to_use_a_tool_it_was_never_given()
    {
        using var backend = new ClaudeCodeCliBackend(Cli);

        var review = backend.ReadResult(
            Envelope(
                structuredOutput: OneFinding,
                permissionDenials: """[{"tool_name": "Bash"}]"""),
            Triaged());

        Assert.NotNull(review.Limitation);
        Assert.Contains("attempted to use a tool", review.Limitation, StringComparison.Ordinal);

        // The findings still stand; the attempt is reported alongside them, not instead.
        Assert.Single(review.Findings);
    }
}

/// <summary>
/// Which backend answers, and the conditions under which none may. The gate keeping the local
/// agent away from software the reader did not write lives in the core rather than in a view,
/// so it cannot be lost to a UI change.
/// </summary>
public class DeepPassBackendSelectionTests
{
    private sealed class FakeBackend(bool bills) : IDeepPassBackend
    {
        public string Description => "a stand-in backend";

        public bool BillsTheReader => bills;

        public decimal? PriceOf(TokenUsage usage) => usage.EstimatedCost;

        public int Reviewed { get; private set; }

        public bool Disposed { get; private set; }

        public Task<FileReview> ReviewAsync(TriagedFile triaged, CancellationToken ct = default)
        {
            Reviewed++;
            return Task.FromResult(new FileReview
            {
                Usage = new TokenUsage { Input = 1_000_000, Output = 1_000_000 },
            });
        }

        public void Dispose() => Disposed = true;
    }

    private static readonly IReadOnlyList<RecoveredFile> Files =
    [
        new()
        {
            RelativePath = "Client.cs",
            Content = "var json = await Http.GetStringAsync(url);",
            Language = RecoveredFile.LanguageOf("Client.cs"),
        },
    ];

    // ---- When the pass is on at all ----------------------------------------

    [Fact]
    public void Is_on_when_the_local_cli_was_chosen_without_a_key() =>
        Assert.True(new ScanOptions { DeepPassUseLocalCli = true }.DeepPassEnabled);

    [Fact]
    public void Is_still_off_when_nothing_was_chosen() =>
        Assert.False(new ScanOptions().DeepPassEnabled);

    // ---- The audience gate -------------------------------------------------

    /// <summary>
    /// The load-bearing restriction. Handing recovered source to an agent that can act on this
    /// machine is defensible when the reader wrote that source; for software from elsewhere it
    /// is the attack the tool exists to warn about.
    /// </summary>
    [Fact]
    public async Task Refuses_the_local_cli_for_an_end_user_audience()
    {
        var result = await DeepPassRunner.RunAsync(
            Files,
            [],
            new ScanOptions { DeepPassUseLocalCli = true, Audience = Audience.EndUser });

        Assert.Empty(result.Findings);
        Assert.Null(result.Backend);

        var limitation = Assert.Single(result.Limitations);
        Assert.Contains("you built yourself", limitation, StringComparison.Ordinal);
    }

    /// <summary>
    /// A refusal says so rather than quietly using the API instead. Somebody who asked for
    /// their subscription to be spent should not find their card charged instead.
    /// </summary>
    [Fact]
    public async Task Does_not_silently_fall_back_to_the_api_when_refused()
    {
        var result = await DeepPassRunner.RunAsync(
            Files,
            [],
            new ScanOptions
            {
                DeepPassUseLocalCli = true,
                DeepPassApiKey = "sk-ant-test",
                Audience = Audience.EndUser,
            });

        Assert.Null(result.Backend);
        Assert.Empty(result.Findings);
    }

    // ---- What the result carries -------------------------------------------

    [Fact]
    public async Task Names_the_backend_that_answered()
    {
        var backend = new FakeBackend(bills: true);

        var result = await DeepPassRunner.RunAsync(
            Files, [], new ScanOptions { DeepPassApiKey = "sk-ant-test" }, backend);

        Assert.Equal("a stand-in backend", result.Backend);
        Assert.Contains(
            result.Limitations,
            l => l.Contains("answered by a stand-in backend", StringComparison.Ordinal));
    }

    /// <summary>
    /// The tokens are real either way. Whether they are a bill is not, and the report needs
    /// the second question answered rather than inferred from the first.
    /// </summary>
    [Fact]
    public async Task Reports_a_cost_only_when_the_reader_was_actually_billed()
    {
        var billed = await DeepPassRunner.RunAsync(
            Files, [], new ScanOptions { DeepPassApiKey = "sk-ant-test" }, new FakeBackend(true));

        var quota = await DeepPassRunner.RunAsync(
            Files, [], new ScanOptions { DeepPassUseLocalCli = true }, new FakeBackend(false));

        Assert.Equal(30.00m, billed.EstimatedCost);
        Assert.Equal(30.00m, billed.BilledCost);

        // Same tokens, same estimate, no bill.
        Assert.Equal(30.00m, quota.EstimatedCost);
        Assert.Null(quota.BilledCost);
    }

    /// <summary>A backend the caller supplied is the caller's to dispose.</summary>
    [Fact]
    public async Task Does_not_dispose_a_backend_it_was_handed()
    {
        var backend = new FakeBackend(bills: true);

        await DeepPassRunner.RunAsync(
            Files, [], new ScanOptions { DeepPassApiKey = "sk-ant-test" }, backend);

        Assert.False(backend.Disposed);
        Assert.Equal(1, backend.Reviewed);
    }
}
