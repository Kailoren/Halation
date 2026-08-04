using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace VibeCheck.Core.DeepPass;

/// <summary>Whether a located CLI can actually answer, and why not when it cannot.</summary>
public sealed record ClaudeCodeCliAuth
{
    public required bool SignedIn { get; init; }

    /// <summary>What to tell the reader when it cannot, phrased as something they can act on.</summary>
    public string? Problem { get; init; }
}

/// <summary>
/// Answers the deep pass through a Claude Code installation the reader already has, on the
/// subscription they are already paying for.
/// </summary>
/// <remarks>
/// <para>
/// A Claude subscription does not cover API usage, so without this somebody already paying for
/// Max would have to buy credits a second time.
/// </para>
/// <para>
/// <b>The security boundary is <c>--tools ""</c>, and it is not a preference.</b> This feeds
/// untrusted source to an agent with shell and filesystem access, so a prompt injection in that
/// code would otherwise run commands on the machine of somebody trying to find out whether the
/// application was safe. Also load-bearing: <c>--safe-mode</c> (no CLAUDE.md, skills, hooks or
/// MCP servers), an empty working directory, <c>--no-session-persistence</c>, and content on
/// stdin rather than in a readable command line.
/// </para>
/// <para>
/// Those rest on third-party flags continuing to mean what they mean, so the route is also
/// gated to the developer audience in <see cref="DeepPassRunner"/> rather than in the UI.
/// </para>
/// </remarks>
public sealed class ClaudeCodeCliBackend : IDeepPassBackend
{
    /// <summary>Matches <see cref="DeepPassClient"/>, so the two backends are comparable.</summary>
    private const string DefaultModel = "claude-opus-5";

    /// <summary>
    /// A hung CLI must not hang the scan. Generous, because a large file under a high effort
    /// level is legitimately slow, but finite.
    /// </summary>
    private static readonly TimeSpan FileTimeout = TimeSpan.FromMinutes(5);

    private readonly ClaudeCodeCli _cli;
    private readonly string _model;
    private readonly string _workingDirectory;
    private readonly string _schema;
    private bool _disposed;

    public ClaudeCodeCliBackend(ClaudeCodeCli cli, string? model = null)
    {
        ArgumentNullException.ThrowIfNull(cli);

        _cli = cli;
        _model = model ?? DefaultModel;
        _schema = JsonSerializer.Serialize(DeepPassPrompt.FindingSchema);

        // Created rather than reused: the agent is pointed at a directory with nothing in it,
        // so there is no configuration, no repository and no source for it to find locally.
        _workingDirectory = Path.Combine(
            Path.GetTempPath(), "vibecheck-deep-pass-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(_workingDirectory);
    }

    /// <inheritdoc/>
    public string Description => $"{_cli.Description}, running {_model}";

    /// <summary>The empty directory the agent is pointed at, so a test can assert it is empty.</summary>
    internal string WorkingDirectory => _workingDirectory;

    /// <summary>
    /// False. The run spends the reader's subscription quota, and nothing is charged to them.
    /// </summary>
    /// <remarks>
    /// The CLI reports a real <c>total_cost_usd</c> even on a subscription, because it prices
    /// what the API would have charged. Printing it would tell somebody whose card was never
    /// touched that they had been billed, so tokens are reported instead.
    /// </remarks>
    public bool BillsTheReader => false;

    /// <summary>
    /// Asks the CLI whether it can authenticate, before a scan starts spending time on files.
    /// </summary>
    /// <remarks>
    /// Installed and signed in are separate facts, and the bundled binary keeps its own
    /// credential rather than sharing the desktop app's. Asked with <c>auth status</c>, which
    /// answers without making a request.
    /// </remarks>
    public static async Task<ClaudeCodeCliAuth> CheckAuthenticationAsync(
        ClaudeCodeCli cli,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cli);

        try
        {
            var (output, _, _) = await RunAsync(
                cli,
                Path.GetTempPath(),
                ["auth", "status"],
                stdin: null,
                TimeSpan.FromSeconds(30),
                cancellationToken).ConfigureAwait(false);

            using var document = JsonDocument.Parse(output);

            var signedIn = document.RootElement.TryGetProperty("loggedIn", out var loggedIn)
                           && loggedIn.ValueKind == JsonValueKind.True;

            return new ClaudeCodeCliAuth
            {
                SignedIn = signedIn,
                Problem = signedIn
                    ? null
                    : "Claude Code is installed but not signed in, so the deep pass could not "
                      + "run. Run \"claude auth login\" in a terminal and scan again.",
            };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or IOException)
        {
            return new ClaudeCodeCliAuth
            {
                SignedIn = false,
                Problem = "Claude Code is installed but did not report its sign-in state, so the "
                          + "deep pass did not run.",
            };
        }
    }

    /// <inheritdoc/>
    public async Task<FileReview> ReviewAsync(
        TriagedFile triaged,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(triaged);
        ObjectDisposedException.ThrowIf(_disposed, this);

        string output;

        try
        {
            var (stdout, stderr, exitCode) = await RunAsync(
                _cli,
                _workingDirectory,
                Arguments(),
                DeepPassPrompt.BuildPrompt(triaged),
                FileTimeout,
                cancellationToken).ConfigureAwait(false);

            // A non-zero exit with nothing parseable on stdout is the only case where stderr is
            // the best description of what went wrong.
            if (string.IsNullOrWhiteSpace(stdout))
            {
                return Failed(
                    triaged,
                    string.IsNullOrWhiteSpace(stderr)
                        ? $"exited with code {exitCode} and said nothing"
                        : Trim(stderr));
            }

            output = stdout;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Failed(triaged, $"took longer than {FileTimeout.TotalMinutes:0} minutes");
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException
                                      or System.ComponentModel.Win32Exception)
        {
            return Failed(triaged, ex.Message);
        }

        return ReadResult(output, triaged);
    }

    /// <summary>
    /// The invocation. Every flag here is either the security boundary described on the class
    /// or a condition of the two backends staying comparable.
    /// </summary>
    internal IReadOnlyList<string> Arguments() =>
    [
        "-p",

        // The boundary. Stated explicitly rather than inferred from a permission mode, because
        // a permission mode governs what is allowed and this governs what exists.
        "--tools", "",

        "--safe-mode",
        "--no-session-persistence",
        "--output-format", "json",
        "--model", _model,

        // Matches the API backend's effort, so the difference between two reports is the
        // application and not the setting.
        "--effort", "medium",

        // Replaces Claude Code's own agent prompt rather than appending to it. Appending would
        // leave a coding agent's instructions in front of a review prompt, and the answer would
        // no longer be the same question the API backend asks.
        "--system-prompt", DeepPassPrompt.SystemPrompt,

        // The same schema object the API backend constrains against, serialised. Structured
        // output arrives as a forced tool call, so a schema run reports stop_reason "tool_use"
        // rather than "end_turn"; that is success, not a tool the agent decided to reach for.
        "--json-schema", _schema,
    ];

    /// <summary>Reads the CLI's result envelope into a review.</summary>
    internal FileReview ReadResult(string output, TriagedFile triaged)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(output);
        }
        catch (JsonException)
        {
            return Failed(triaged, "returned something that was not JSON");
        }

        using (document)
        {
            var root = document.RootElement;
            var usage = ReadUsage(root);

            // Checked before anything else. A failure still arrives with a success-shaped
            // envelope, so branching on "subtype" would read a failed run as a clean one.
            if (root.TryGetProperty("is_error", out var isError)
                && isError.ValueKind == JsonValueKind.True)
            {
                return Failed(triaged, Trim(Text(root, "result") ?? "reported an error"), usage);
            }

            var stopReason = Text(root, "stop_reason");

            if (stopReason == "refusal")
            {
                return new FileReview
                {
                    // Unlike the API backend, which re-serves a decline on a substitute model
                    // inside the same call, nothing here retries. The file is simply not
                    // covered, and a reader comparing this report against an API-backed one is
                    // owed that difference rather than left to assume equal coverage.
                    Limitation =
                        $"The deep pass was declined for {triaged.File.RelativePath} on policy "
                        + "grounds. Claude Code has no substitute model to fall back to, so that "
                        + "file was not reviewed at all.",
                    Usage = usage,
                };
            }

            if (stopReason == "max_tokens")
            {
                return new FileReview
                {
                    Limitation = $"The review of {triaged.File.RelativePath} was cut off before it "
                                 + "finished, so that file was only partly examined.",
                    Usage = usage,
                };
            }

            var answer = ReadFindings(root, triaged);

            if (answer is null)
            {
                return Failed(triaged, "returned no structured answer", usage);
            }

            return new FileReview
            {
                Findings = answer.Findings,
                LowConfidenceDiscarded = answer.LowConfidenceDiscarded,
                Usage = usage,
                ServedByFallback = SubstituteModelAnswered(root),
                Limitation = ToolUseAttempted(root)
                    ? $"While reviewing {triaged.File.RelativePath}, the agent attempted to use a "
                      + "tool despite having none. That is worth knowing: it can mean the code "
                      + "being reviewed contains text aimed at the reviewer rather than at a "
                      + "compiler."
                    : null,
            };
        }
    }

    /// <summary>
    /// The findings, preferring the pre-parsed object the CLI supplies over re-parsing the text.
    /// Null when neither is present, which is a failure rather than an empty result.
    /// </summary>
    private static DeepPassAnswer? ReadFindings(JsonElement root, TriagedFile triaged)
    {
        if (root.TryGetProperty("structured_output", out var structured)
            && structured.ValueKind == JsonValueKind.Object)
        {
            return DeepPassPrompt.Parse(structured.GetRawText(), triaged);
        }

        return Text(root, "result") is { Length: > 0 } text
            ? DeepPassPrompt.Parse(text, triaged)
            : null;
    }

    /// <summary>
    /// Whether a model other than the requested one produced the answer.
    /// </summary>
    /// <remarks>
    /// Read from <c>modelUsage</c> rather than assumed. A run legitimately involves more than
    /// one model, because the CLI makes small auxiliary calls of its own, so the question is
    /// whether the requested model is among them and not whether it was the only one.
    /// </remarks>
    private bool SubstituteModelAnswered(JsonElement root)
    {
        if (!root.TryGetProperty("modelUsage", out var models)
            || models.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var any = false;

        foreach (var model in models.EnumerateObject())
        {
            any = true;

            if (model.Name == _model
                || (model.Value.ValueKind == JsonValueKind.Object
                    && Text(model.Value, "canonicalModel") == _model))
            {
                return false;
            }
        }

        return any;
    }

    /// <summary>
    /// Whether the agent tried to act despite having no tools. Reported rather than ignored:
    /// with <c>--tools ""</c> there is nothing to reach for, so an attempt says something about
    /// the text that was fed in.
    /// </summary>
    private static bool ToolUseAttempted(JsonElement root) =>
        root.TryGetProperty("permission_denials", out var denials)
        && denials.ValueKind == JsonValueKind.Array
        && denials.GetArrayLength() > 0;

    private static TokenUsage ReadUsage(JsonElement root)
    {
        if (!root.TryGetProperty("usage", out var usage) || usage.ValueKind != JsonValueKind.Object)
        {
            return new TokenUsage();
        }

        long Count(string name) =>
            usage.TryGetProperty(name, out var value) && value.TryGetInt64(out var count)
                ? count
                : 0;

        return new TokenUsage
        {
            Input = Count("input_tokens"),
            Output = Count("output_tokens"),
            CacheWrite = Count("cache_creation_input_tokens"),
            CacheRead = Count("cache_read_input_tokens"),
        };
    }

    private static FileReview Failed(TriagedFile triaged, string what, TokenUsage? usage = null) =>
        new()
        {
            Limitation = $"The deep pass failed for {triaged.File.RelativePath}: Claude Code "
                         + $"{what}. That file was not reviewed.",
            Usage = usage ?? new TokenUsage(),
        };

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>Keeps an error message to a sentence, since it goes into a report.</summary>
    private static string Trim(string message)
    {
        var single = string.Join(' ', message.Split(
            ['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        return single.Length > 300 ? single[..300] + "..." : single;
    }

    /// <summary>
    /// Runs the executable and collects what it said.
    /// </summary>
    /// <remarks>
    /// Arguments go through <see cref="ProcessStartInfo.ArgumentList"/>, which escapes each one
    /// for the platform. That matters more than usual here: two of the arguments are a JSON
    /// schema and a multi-line system prompt, and hand-built command lines mangle both.
    /// </remarks>
    /// <summary>
    /// UTF-8 with no byte order mark, on every stream to and from the agent.
    /// </summary>
    /// <remarks>
    /// Without this the pipes are decoded with the console's own code page, which on a British
    /// or American Windows install is Windows-1252. The agent emits UTF-8, so every character
    /// outside ASCII arrived as its bytes read one at a time: an em dash in a finding's prose
    /// reached the report as <c>â€"</c>. It was visible in the interface for as long as the deep
    /// pass has existed, in exactly the text a reader is meant to trust most.
    ///
    /// <para>
    /// No byte order mark, deliberately. The input stream carries a JSON document, and a mark
    /// at the front of it is three bytes the parser at the other end is not expecting.
    /// </para>
    /// </remarks>
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// Builds the process description, apart from the arguments.
    /// </summary>
    /// <remarks>
    /// Separated so the encodings can be asserted directly. They are invisible in behaviour
    /// until somebody scans a file whose findings contain a character outside ASCII, which is
    /// how they came to be missing in the first place.
    /// </remarks>
    internal static ProcessStartInfo BuildStartInfo(ClaudeCodeCli cli, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(cli);

        var startInfo = new ProcessStartInfo
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = Utf8,
            StandardOutputEncoding = Utf8,
            StandardErrorEncoding = Utf8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        // A batch shim cannot be started directly when the shell is bypassed, and an npm global
        // install is exactly that. Routed through the interpreter rather than excluded, since
        // for some readers it is the only Claude Code they have.
        if (Path.GetExtension(cli.Path) is ".cmd" or ".bat")
        {
            startInfo.FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add(cli.Path);
        }
        else
        {
            startInfo.FileName = cli.Path;
        }

        return startInfo;
    }

    private static async Task<(string Output, string Error, int ExitCode)> RunAsync(
        ClaudeCodeCli cli,
        string workingDirectory,
        IReadOnlyList<string> arguments,
        string? stdin,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var startInfo = BuildStartInfo(cli, workingDirectory);

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };

        process.Start();

        using var timer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timer.CancelAfter(timeout);

        // Started before the write completes and awaited after, so a process that answers
        // before it has read everything cannot deadlock against a full pipe.
        var output = process.StandardOutput.ReadToEndAsync(timer.Token);
        var error = process.StandardError.ReadToEndAsync(timer.Token);

        try
        {
            if (stdin is not null)
            {
                await process.StandardInput.WriteAsync(stdin.AsMemory(), timer.Token)
                    .ConfigureAwait(false);
            }

            process.StandardInput.Close();

            await process.WaitForExitAsync(timer.Token).ConfigureAwait(false);

            return (await output.ConfigureAwait(false), await error.ConfigureAwait(false),
                    process.ExitCode);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            throw;
        }
    }

    private static void Kill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException
                                      or System.ComponentModel.Win32Exception
                                      or NotSupportedException)
        {
            // Already gone, or beyond our reach. Either way there is nothing further to do.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            if (Directory.Exists(_workingDirectory))
            {
                Directory.Delete(_workingDirectory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The directory was created empty and nothing writes to it, so leaving one behind
            // in the temporary directory is not worth failing a scan over.
        }
    }
}
