using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

using VibeCheck.Core;
using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Tests;

/// <summary>
/// The deep pass answered by something other than Anthropic.
/// </summary>
/// <remarks>
/// One backend covers every hosted provider worth naming and both local runtimes, because they
/// all speak the same chat-completions shape. These tests hold the parts that are easy to get
/// subtly wrong and impossible to notice: what is actually sent, what happens when a server
/// cannot do structured output, and that nothing invents a dollar figure for a model it has
/// never heard of.
/// </remarks>
public sealed class OpenAiCompatibleBackendTests : IDisposable
{
    private readonly StubEndpoint _server = new();

    public void Dispose() => _server.Dispose();

    private static TriagedFile File(string content = "const x = req.query.id;") =>
        new()
        {
            File = new RecoveredFile
            {
                RelativePath = "src/app.js",
                Content = content,
                Language = SourceLanguage.JavaScript,
            },
            Reason = "handles untrusted input",
        };

    private OpenAiCompatibleBackend Backend(string model = "qwen2.5-coder") =>
        new(_server.Uri, apiKey: "sk-test", model: model, handler: _server.Handler);

    // ---- What actually goes over the wire -----------------------------------

    [Fact]
    public async Task Sends_the_shared_prompt_and_the_named_model()
    {
        _server.Reply(Answer("[]"));

        using var backend = Backend();
        await backend.ReviewAsync(File());

        var sent = _server.LastRequest!;

        Assert.Equal("qwen2.5-coder", sent.RootElement.GetProperty("model").GetString());

        var messages = sent.RootElement.GetProperty("messages");
        Assert.Equal(2, messages.GetArrayLength());
        Assert.Equal("system", messages[0].GetProperty("role").GetString());

        // The same question the other backends ask. Two scans must differ because the
        // application differed, not because the plumbing did.
        Assert.Contains(
            "A deterministic pattern scanner has already run",
            messages[0].GetProperty("content").GetString()!,
            StringComparison.Ordinal);

        Assert.Contains(
            "src/app.js",
            messages[1].GetProperty("content").GetString()!,
            StringComparison.Ordinal);

        // Sampling off, so an unchanged application does not produce a different report.
        Assert.Equal(0, sent.RootElement.GetProperty("temperature").GetInt32());
    }

    [Fact]
    public async Task Reads_findings_and_marks_them_advisory()
    {
        _server.Reply(Answer("""
            [{"title":"Unvalidated redirect","severity":"high","user_severity":"medium",
              "user_impact":"A link could send you somewhere else.","file":"src/app.js",
              "evidence":"res.redirect(req.query.next)","reachability":"reachable",
              "why_rules_miss_it":"the guard is incomplete","remediation":"allowlist it",
              "confidence":"high"}]
            """));

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        var finding = Assert.Single(review.Findings);

        Assert.Equal("Unvalidated redirect", finding.Title);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Severity.Medium, finding.UserSeverity);

        // The guarantee the whole pass rests on: inferred findings can never block.
        Assert.Equal(FindingSource.Assisted, finding.Source);
        Assert.False(finding.IsBlocking);
    }

    [Fact]
    public async Task Reports_the_tokens_the_endpoint_declared()
    {
        _server.Reply(Answer("[]", promptTokens: 1234, completionTokens: 56));

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        Assert.Equal(1234, review.Usage.Input);
        Assert.Equal(56, review.Usage.Output);
    }

    // ---- Servers that cannot do everything ----------------------------------

    /// <summary>
    /// Several compatible servers implement <c>json_object</c> but not <c>json_schema</c>.
    /// Rather than making the reader know which they have, the first refusal downgrades.
    /// </summary>
    [Fact]
    public async Task Retries_without_the_schema_when_the_endpoint_rejects_it()
    {
        _server.ReplyOnce(HttpStatusCode.BadRequest, """{"error":{"message":"response_format"}}""");
        _server.Reply(Answer("[]"));

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        Assert.Null(review.Limitation);
        Assert.Equal(2, _server.Requests);

        // And having learned, it does not pay for the discovery twice.
        await backend.ReviewAsync(File());
        Assert.Equal(3, _server.Requests);

        Assert.Equal(
            "json_object",
            _server.LastRequest!.RootElement.GetProperty("response_format")
                .GetProperty("type").GetString());
    }

    /// <summary>A refusal arrives beside an empty answer, so it has to be read first.</summary>
    [Fact]
    public async Task Treats_a_refusal_as_a_limitation_rather_than_a_clean_file()
    {
        _server.Reply("""
            {"choices":[{"message":{"role":"assistant","content":null,
              "refusal":"I cannot help with that."}}]}
            """);

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        Assert.Empty(review.Findings);
        Assert.NotNull(review.Limitation);
        Assert.Contains("declined", review.Limitation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_server_error_costs_one_file_rather_than_the_scan()
    {
        _server.Reply(HttpStatusCode.InternalServerError, "upstream exploded");

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        Assert.Empty(review.Findings);
        Assert.NotNull(review.Limitation);
        Assert.Contains("500", review.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nonsense_in_the_answer_yields_nothing_rather_than_throwing()
    {
        _server.Reply(Answer("not json at all", raw: true));

        using var backend = Backend();
        var review = await backend.ReviewAsync(File());

        Assert.Empty(review.Findings);
    }

    // ---- Where the source code is allowed to go -----------------------------

    /// <summary>
    /// The request carries recovered source. Loopback in the clear is the normal shape for a
    /// local model; anything crossing a network has to be encrypted.
    /// </summary>
    [Theory]
    [InlineData("http://localhost:11434/v1/chat/completions", true)]
    [InlineData("http://127.0.0.1:1234/v1/chat/completions", true)]
    [InlineData("https://api.openai.com/v1/chat/completions", true)]
    [InlineData("http://example.invalid/v1/chat/completions", false)]
    [InlineData("ftp://example.invalid/v1", false)]
    public void Only_a_local_endpoint_may_be_unencrypted(string url, bool allowed) =>
        Assert.Equal(allowed, OpenAiCompatibleBackend.RejectEndpoint(new Uri(url)) is null);

    /// <summary>
    /// The floor is this application's, not the operating system's.
    /// </summary>
    /// <remarks>
    /// Left unset, .NET takes the host default, which a machine with an edited policy or an
    /// older build can set lower than anyone here would choose. Asserted rather than assumed
    /// because nothing about a working request would reveal that it had been downgraded.
    /// </remarks>
    [Fact]
    public void Deprecated_TLS_versions_are_refused()
    {
        using var transport = OpenAiCompatibleBackend.Transport();

        var enabled = transport.SslOptions.EnabledSslProtocols;

        Assert.True(enabled.HasFlag(SslProtocols.Tls13));
        Assert.True(enabled.HasFlag(SslProtocols.Tls12));

#pragma warning disable SYSLIB0039 // Naming them is the point: these must not be negotiable.
        Assert.False(enabled.HasFlag(SslProtocols.Tls11));
        Assert.False(enabled.HasFlag(SslProtocols.Tls));
#pragma warning restore SYSLIB0039

        // And not "whatever the host prefers", which is what an unset value means.
        Assert.NotEqual(SslProtocols.None, enabled);
    }

    [Fact]
    public void The_reader_is_told_which_host_their_code_went_to()
    {
        using var backend = new OpenAiCompatibleBackend(
            new Uri("https://openrouter.ai/api/v1/chat/completions"), "k", "some/model");

        Assert.Contains("openrouter.ai", backend.Description, StringComparison.Ordinal);
        Assert.Contains("some/model", backend.Description, StringComparison.Ordinal);
    }

    // ---- Which backend a scan chooses ---------------------------------------

    /// <summary>
    /// With no files to review the pass returns as soon as it has picked something, which is
    /// exactly the part worth asserting and needs no network to assert it.
    /// </summary>
    private static async Task<DeepPassResult> ChooseAsync(ScanOptions options) =>
        await DeepPassRunner.RunAsync([], [], options);

    [Fact]
    public async Task A_nominated_endpoint_wins_over_a_subscription()
    {
        var result = await ChooseAsync(ScanOptions.Default with
        {
            DeepPassEndpoint = new Uri("http://localhost:11434/v1/chat/completions"),
            DeepPassModel = "qwen2.5-coder",

            // Both set. Somebody who configured a local model must not be quietly answered by
            // a subscription, which would send their code somewhere they did not choose.
            DeepPassUseLocalCli = true,
        });

        Assert.Contains("localhost", result.Backend!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unencrypted_remote_endpoint_is_refused_before_anything_is_sent()
    {
        var result = await ChooseAsync(ScanOptions.Default with
        {
            DeepPassEndpoint = new Uri("http://example.invalid/v1/chat/completions"),
            DeepPassModel = "some-model",
        });

        Assert.Null(result.Backend);
        Assert.Contains(
            "https", Assert.Single(result.Limitations), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_endpoint_with_no_model_named_is_refused()
    {
        var result = await ChooseAsync(ScanOptions.Default with
        {
            DeepPassEndpoint = new Uri("https://api.openai.com/v1/chat/completions"),
        });

        Assert.Null(result.Backend);
        Assert.Contains(
            "model", Assert.Single(result.Limitations), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And configuring one is enough to turn the pass on, since nominating an endpoint is as
    /// deliberate an act as supplying a key.
    /// </summary>
    [Fact]
    public void An_endpoint_alone_enables_the_deep_pass() =>
        Assert.True((ScanOptions.Default with
        {
            DeepPassEndpoint = new Uri("http://localhost:11434/v1/chat/completions"),
        }).DeepPassEnabled);

    // ---- Helpers ------------------------------------------------------------

    private static string Answer(string findingsJson, bool raw = false,
        int promptTokens = 0, int completionTokens = 0)
    {
        var content = raw ? findingsJson : $$"""{"findings":{{findingsJson}}}""";

        return JsonSerializer.Serialize(new
        {
            choices = new[] { new { message = new { role = "assistant", content } } },
            usage = new { prompt_tokens = promptTokens, completion_tokens = completionTokens },
        });
    }

    /// <summary>
    /// A chat-completions server, in as few lines as will hold a real request.
    /// </summary>
    /// <remarks>
    /// A handler rather than a socket: what these tests need to assert is the body that was
    /// sent and the behaviour on each reply, and a real listener would add ports and timing to
    /// a test that is about neither.
    /// </remarks>
    private sealed class StubEndpoint : IDisposable
    {
        private readonly Queue<(HttpStatusCode Status, string Body)> _once = new();
        private (HttpStatusCode Status, string Body) _standing = (HttpStatusCode.OK, "{}");

        public Uri Uri { get; } = new("https://stub.invalid/v1/chat/completions");

        public HttpMessageHandler Handler { get; }

        public int Requests { get; private set; }

        public JsonDocument? LastRequest { get; private set; }

        public StubEndpoint() => Handler = new Stub(this);

        public void Reply(string body) => _standing = (HttpStatusCode.OK, body);

        public void Reply(HttpStatusCode status, string body) => _standing = (status, body);

        public void ReplyOnce(HttpStatusCode status, string body) => _once.Enqueue((status, body));

        public void Dispose()
        {
            Handler.Dispose();
            LastRequest?.Dispose();
        }

        private sealed class Stub(StubEndpoint owner) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                owner.Requests++;

                var body = await request.Content!.ReadAsStringAsync(cancellationToken);
                owner.LastRequest?.Dispose();
                owner.LastRequest = JsonDocument.Parse(body);

                var (status, reply) = owner._once.Count > 0
                    ? owner._once.Dequeue()
                    : owner._standing;

                return new HttpResponseMessage(status)
                {
                    Content = new StringContent(reply, Encoding.UTF8, "application/json"),
                };
            }
        }
    }
}
