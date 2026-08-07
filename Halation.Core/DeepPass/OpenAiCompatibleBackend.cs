using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Halation.Core.Rules;

namespace Halation.Core.DeepPass;

/// <summary>
/// Answers the deep pass through any endpoint that speaks the OpenAI chat-completions shape.
/// </summary>
/// <remarks>
/// <para>
/// One implementation, and it is deliberately the widest one available. OpenAI, OpenRouter,
/// Google's compatibility endpoint, Groq, Together, DeepSeek, Mistral and every other hosted
/// provider of consequence expose this shape, and so do Ollama and LM Studio running on the
/// reader's own machine. A per-provider SDK would have bought one provider each; a base URL and
/// this request body buys all of them, including the offline case, which is the half of the
/// problem no API key solves.
/// </para>
/// <para>
/// Written against <c>HttpClient</c> rather than a vendor SDK on purpose. An SDK encodes one
/// provider's assumptions about routing, retries and error shapes, and the point here is to be
/// held to none of them.
/// </para>
/// <para>
/// <b>It cannot price its own tokens and does not pretend to.</b> The model behind an arbitrary
/// base URL might cost fifteen dollars a million tokens or nothing at all, and a report that
/// printed a dollar figure at Anthropic's rates for a run against a local model would be making
/// exactly the kind of confident false statement this tool exists not to make. It reports tokens
/// and lets the report say tokens.
/// </para>
/// </remarks>
public sealed class OpenAiCompatibleBackend : IDeepPassBackend
{
    /// <summary>Room for the findings. Matches the API backend so answers stay comparable.</summary>
    private const int MaxTokens = 16_000;

    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly Uri _endpoint;
    private readonly string _model;

    /// <summary>
    /// Whether this endpoint has accepted a schema-constrained request.
    /// </summary>
    /// <remarks>
    /// Not every compatible server implements <c>json_schema</c>; several only manage
    /// <c>json_object</c>, and a few neither. Rather than ask the reader to know which they have,
    /// the first refusal downgrades and the rest of the scan proceeds at the lower setting. Tried
    /// in this order because a schema-constrained answer is structurally valid rather than
    /// merely likely to be.
    /// </remarks>
    private bool _schemaSupported = true;

    public OpenAiCompatibleBackend(
        Uri endpoint,
        string? apiKey,
        string model,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);

        _endpoint = endpoint;
        _model = model;

        _ownsClient = handler is null;
        _http = handler is null
            ? new HttpClient(
                new SocketsHttpHandler { ConnectCallback = ConnectAsync }, disposeHandler: true)
            : new HttpClient(handler, disposeHandler: false);

        _http.Timeout = PatienceFor(endpoint);

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", apiKey.Trim());
        }
    }

    /// <summary>
    /// How long to wait for one file's answer, which is not the same question on a hosted
    /// provider as on the reader's own graphics card.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Measured, after a whole pass failed.</b> Five minutes suits a hosted provider, where a
    /// request that has not answered by then is wedged rather than working. It is not enough for
    /// a local model, and the arithmetic says so exactly: a 7B model on an 8GB card generates at
    /// about 69 tokens a second, so the <see cref="MaxTokens"/> ceiling of 16,000 is <b>232
    /// seconds of generation on its own</b>, and reading a file at this pass's
    /// sixty-thousand-character limit adds roughly 43 seconds of prompt processing on top. That
    /// lands within a few seconds of five minutes, which is why <i>every</i> request was
    /// cancelled and why they were a suspiciously round five minutes apart. The scan was not
    /// slow, it was failing.
    /// </para>
    /// <para>
    /// The ceiling only binds when the model rambles to its output limit, which small models do
    /// and frontier models mostly do not. That is the case worth surviving: it is the same model
    /// size this application recommends to somebody with an 8GB card.
    /// </para>
    /// <para>
    /// Loopback is the discriminator because it is the one that tracks the actual cause. A local
    /// endpoint is slow in proportion to the reader's hardware, which this application does not
    /// get to choose; a hosted one that goes quiet for five minutes is broken, and failing fast
    /// there is the useful behaviour. Raising the ceiling for everybody would have hidden that.
    /// </para>
    /// <para>
    /// This governs one file, not the pass, so a large application is bounded by the file ceiling
    /// rather than by this. A timeout is still reported per file rather than absorbed, so a
    /// machine too slow even for this says so instead of returning a quiet scan.
    /// </para>
    /// </remarks>
    private static TimeSpan PatienceFor(Uri endpoint) =>
        endpoint.IsLoopback ? TimeSpan.FromMinutes(30) : TimeSpan.FromMinutes(5);

    /// <summary>
    /// Names the host as well as the model, because the reader is entitled to know where their
    /// source code was sent.
    /// </summary>
    /// <remarks>
    /// The deep pass uploads recovered source, and with a configurable endpoint the destination
    /// is a choice rather than a constant. A report that said only "an OpenAI-compatible
    /// endpoint" would be describing the one fact about this run that nobody can infer.
    /// </remarks>
    public string Description =>
        $"an OpenAI-compatible endpoint at {_endpoint.Host} ({_model}){SecurityNote}";

    /// <summary>
    /// False. Some endpoints are free and some are local, and none of them can be priced from
    /// here, so no run through this backend is reported as money.
    /// </summary>
    public bool BillsTheReader => false;

    /// <inheritdoc/>
    public decimal? PriceOf(TokenUsage usage) => null;

    /// <summary>
    /// The versions of TLS this backend will negotiate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stated rather than inherited. Left unset, .NET takes the operating system's default,
    /// which on a current Windows means 1.2 and 1.3 and on a machine with an edited policy or
    /// an older build can mean less. The payload is the reader's recovered source code, so the
    /// floor belongs in this application rather than in whatever the host was configured with
    /// years ago.
    /// </para>
    /// <para>
    /// <b>Not 1.3 only, deliberately.</b> Requiring it would refuse a real slice of working
    /// endpoints: self-hosted inference servers behind an older reverse proxy, corporate
    /// gateways, and TLS-inspecting middleboxes commonly terminate at 1.2. A security tool that
    /// fails to connect with an opaque error does not make anybody safer, it sends them back to
    /// pasting their code into a web page. 1.2 with modern cipher suites is not broken, and 1.3
    /// is preferred automatically wherever the other end can do it.
    /// </para>
    /// </remarks>
    public const System.Security.Authentication.SslProtocols Protocols =
        System.Security.Authentication.SslProtocols.Tls12
        | System.Security.Authentication.SslProtocols.Tls13;

    /// <summary>The transport used when the caller did not supply one, with the floor applied.</summary>
    public static SocketsHttpHandler Transport() => new()
    {
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            EnabledSslProtocols = Protocols,
        },
    };

    /// <summary>
    /// What was actually negotiated on the connection that carried the source code, or null
    /// when nothing has been sent yet or the endpoint was local and unencrypted.
    /// </summary>
    private System.Security.Authentication.SslProtocols? _negotiated;

    /// <summary>
    /// Establishes the connection by hand so the negotiated protocol can be read back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The handshake is performed here rather than left to the handler, because the version
    /// that was agreed is not otherwise observable from a completed request, and a report
    /// claiming the code went out over TLS 1.3 has to be reporting something it saw rather than
    /// something it configured. Returning an <see cref="System.Net.Security.SslStream"/> tells
    /// <see cref="SocketsHttpHandler"/> the transport is already secured, so it does not
    /// negotiate a second time.
    /// </para>
    /// <para>
    /// The plaintext branch is reachable only for loopback, which
    /// <see cref="RejectEndpoint"/> has already established is the sole case where a local
    /// model may be reached without TLS. Nothing else gets here unencrypted.
    /// </para>
    /// </remarks>
    private async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var socket = new System.Net.Sockets.Socket(
            System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp)
        {
            NoDelay = true,
        };

        try
        {
            await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);

            var network = new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);

            if (!string.Equals(_endpoint.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                return network;
            }

            var secured = new System.Net.Security.SslStream(network, leaveInnerStreamOpen: false);

            try
            {
                await secured.AuthenticateAsClientAsync(
                    new System.Net.Security.SslClientAuthenticationOptions
                    {
                        TargetHost = context.DnsEndPoint.Host,
                        EnabledSslProtocols = Protocols,
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await secured.DisposeAsync().ConfigureAwait(false);
                throw;
            }

            _negotiated = secured.SslProtocol;

            return secured;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>How the connection is named in the report, or empty before one has been made.</summary>
    private string SecurityNote => _negotiated switch
    {
        System.Security.Authentication.SslProtocols.Tls13 => ", over TLS 1.3",
        System.Security.Authentication.SslProtocols.Tls12 => ", over TLS 1.2",
        null when _endpoint.IsLoopback => ", on this machine",
        null => string.Empty,
        var other => $", over {other}",
    };

    /// <summary>
    /// Whether source code sent to this endpoint would leave the machine in the clear.
    /// </summary>
    /// <remarks>
    /// Loopback over plain HTTP is the normal and correct shape for a local model, so it is
    /// allowed. Anything else must be TLS: the payload is the reader's recovered source, and
    /// sending that across a network unencrypted to satisfy a configuration typo is not a
    /// trade this tool should make silently.
    /// </remarks>
    public static string? RejectEndpoint(Uri? endpoint)
    {
        if (endpoint is null || !endpoint.IsAbsoluteUri)
        {
            return "The deep pass endpoint must be a complete URL, for example "
                   + "https://api.openai.com/v1 or http://localhost:11434/v1.";
        }

        if (endpoint.Scheme is not ("http" or "https"))
        {
            return $"The deep pass endpoint must be http or https, not {endpoint.Scheme}.";
        }

        if (endpoint.Scheme == "http" && !endpoint.IsLoopback)
        {
            return "The deep pass endpoint must use https unless it is on this machine. The "
                   + "request carries this application's recovered source code, which should "
                   + "not cross a network unencrypted.";
        }

        return null;
    }

    /// <inheritdoc/>
    public async Task<FileReview> ReviewAsync(
        TriagedFile triaged,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        try
        {
            var review = await AskAsync(triaged, _schemaSupported, cancellationToken)
                .ConfigureAwait(false);

            // A server that cannot constrain to a schema says so with a 400 naming the field.
            // Downgrading once and retrying costs one extra request on the first file and
            // nothing after, which is cheaper than making the reader configure it.
            if (review is null && _schemaSupported)
            {
                _schemaSupported = false;

                return await AskAsync(triaged, schema: false, cancellationToken)
                           .ConfigureAwait(false)
                       ?? Failed(triaged, "the endpoint rejected the request twice");
            }

            return review ?? Failed(triaged, "the endpoint rejected the request");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Failed(triaged, "the endpoint did not answer in time");
        }
        catch (HttpRequestException ex)
        {
            return Failed(triaged, ex.Message);
        }
        catch (JsonException)
        {
            return Failed(triaged, "the endpoint's reply was not JSON");
        }
    }

    /// <summary>
    /// One request. Returns null when the endpoint refused the request itself, which is the
    /// signal to retry without the schema.
    /// </summary>
    private async Task<FileReview?> AskAsync(
        TriagedFile triaged,
        bool schema,
        CancellationToken cancellationToken)
    {
        using var response = await _http
            .PostAsJsonAsync(_endpoint, BuildBody(triaged, schema, out var promptChars), cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            return (int)response.StatusCode == 400 ? null : Failed(
                triaged,
                $"the endpoint answered {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        using var document = await response.Content
            .ReadFromJsonAsync<JsonDocument>(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new JsonException("empty body");

        var root = document.RootElement;

        if (!root.TryGetProperty("choices", out var choices)
            || choices.ValueKind != JsonValueKind.Array
            || choices.GetArrayLength() == 0)
        {
            return Failed(triaged, "the endpoint returned no answer");
        }

        var message = choices[0].TryGetProperty("message", out var m) ? m : default;

        // A refusal arrives as a populated field beside an empty content, so it has to be read
        // before the content is, exactly as on the API backend. Asking a model to find
        // weaknesses in code is squarely what safety classifiers watch for.
        if (message.ValueKind == JsonValueKind.Object
            && message.TryGetProperty("refusal", out var refusal)
            && refusal.ValueKind == JsonValueKind.String
            && refusal.GetString() is { Length: > 0 } refused)
        {
            return Failed(triaged, $"the model declined to review it: {refused}");
        }

        var content = message.ValueKind == JsonValueKind.Object
                      && message.TryGetProperty("content", out var c)
            ? c.GetString()
            : null;

        var usage = ReadUsage(root);

        // Before the answer is read, not after. A review of a file the model was only shown the
        // tail of is not a weaker review, it is a review of different code, and its findings are
        // worse than none: the guard that makes a pattern safe is usually above the line that
        // matches, so a truncated file reads as an unguarded one.
        if (DiscardedInput(promptChars, usage) is { } truncation)
        {
            return Failed(triaged, truncation, usage);
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return Failed(triaged, "the endpoint returned an empty answer", usage);
        }

        var answer = DeepPassPrompt.Parse(content, triaged);

        return new FileReview
        {
            Findings = answer.Findings,
            LowConfidenceDiscarded = answer.LowConfidenceDiscarded,
            Explains = answer.Explains,
            Usage = usage,
        };
    }

    /// <summary>
    /// The most characters one token is taken to stand for, used only as a floor.
    /// </summary>
    /// <remarks>
    /// Deliberately generous. Source code and English both tokenise at roughly three to four
    /// characters per token, so six is comfortably past anything a real tokeniser produces, and
    /// the check therefore fires only when the shortfall cannot be explained by whose tokeniser
    /// ran. Being wrong in this direction means missing a mild truncation; being wrong in the
    /// other would mean discarding a review that was fine, which is the more expensive mistake
    /// because it is invisible.
    /// </remarks>
    private const int MaxCharsPerToken = 6;

    /// <summary>
    /// Whether the endpoint silently dropped part of the prompt, and how to say so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The transport cannot report this, so it has to be inferred.</b> A server whose context
    /// is smaller than the prompt does not refuse the request: it discards the overflow and
    /// answers 200 with a well-formed reply, and nothing in the chat-completions shape carries a
    /// truncation flag. The only evidence is arithmetic: a prompt of a known length cannot
    /// encode into fewer tokens than its characters allow, so a reported count far below that
    /// floor means the server did not have the whole thing.
    /// </para>
    /// <para>
    /// Measured against Ollama 0.32.6, which was the case that produced this: its input ceiling
    /// is about half the context, so a default 4096-token context accepted 2050 tokens and threw
    /// away 87% of a large file, then answered confidently about the remainder. Six findings in
    /// that scan were of the form "incomplete guard", which is what a file reads like when the
    /// guard was in the discarded part.
    /// </para>
    /// <para>
    /// Silent when the endpoint reports no usage at all, which several local servers do not.
    /// Absence of the counter is not evidence of truncation, and inventing a limitation from a
    /// missing field would be the same error in the other direction.
    /// </para>
    /// </remarks>
    private static string? DiscardedInput(int promptChars, TokenUsage usage)
    {
        if (usage.Input <= 0 || promptChars <= 0)
        {
            return null;
        }

        var floor = promptChars / MaxCharsPerToken;

        if (usage.Input >= floor)
        {
            return null;
        }

        return $"the endpoint read {usage.Input:N0} tokens of a prompt that cannot be shorter "
               + $"than about {floor:N0}, so most of the file was dropped before the model saw "
               + "it. Raise the context length where the model is served, then scan again";
    }

    private object BuildBody(TriagedFile triaged, bool schema, out int promptChars)
    {
        // The schema is restated in the prompt whenever it cannot be enforced, so a server with
        // no structured-output support still knows the shape it is being asked for. Belt and
        // braces on purpose: the parser is forgiving, but a reply in the right shape costs
        // nothing and a reply in the wrong one costs the file.
        var instruction = schema
            ? DeepPassPrompt.SystemPrompt
            : DeepPassPrompt.SystemPrompt
              + "\n\nAnswer with JSON only, matching this schema exactly:\n"
              + JsonSerializer.Serialize(DeepPassPrompt.FindingSchema);

        var prompt = DeepPassPrompt.BuildPrompt(triaged);

        // Both halves, because both are sent and a server truncating the request drops from the
        // whole conversation rather than from the file alone.
        promptChars = instruction.Length + prompt.Length;

        var body = new Dictionary<string, object>
        {
            ["model"] = _model,
            ["max_tokens"] = MaxTokens,

            // Deterministic as the endpoint allows. Two scans of one unchanged application
            // disagreeing because a model was sampling is noise a reader cannot act on.
            ["temperature"] = 0,
            ["messages"] = new object[]
            {
                new { role = "system", content = instruction },
                new { role = "user", content = prompt },
            },
        };

        body["response_format"] = schema
            ? new
            {
                type = "json_schema",
                json_schema = new
                {
                    name = "vibecheck_findings",
                    strict = true,
                    schema = DeepPassPrompt.FindingSchema,
                },
            }
            : new { type = "json_object" };

        return body;
    }

    /// <summary>
    /// Reads whatever the endpoint chose to report about token use.
    /// </summary>
    /// <remarks>
    /// Absent on several local servers, and zero is the honest answer there rather than a
    /// guess. Cache fields are not read: they are not part of this shape, and inventing them
    /// would put numbers in a report that no endpoint reported.
    /// </remarks>
    private static TokenUsage ReadUsage(JsonElement root)
    {
        if (!root.TryGetProperty("usage", out var usage) || usage.ValueKind != JsonValueKind.Object)
        {
            return new TokenUsage();
        }

        long Read(string name) =>
            usage.TryGetProperty(name, out var value) && value.TryGetInt64(out var number)
                ? number
                : 0;

        return new TokenUsage { Input = Read("prompt_tokens"), Output = Read("completion_tokens") };
    }

    private static FileReview Failed(TriagedFile triaged, string why, TokenUsage? usage = null) =>
        new()
        {
            Limitation = $"{triaged.File.RelativePath} was not reviewed: {Redaction.Scrub(why)}.",
            Usage = usage ?? new TokenUsage(),
        };

    public void Dispose()
    {
        if (_ownsClient)
        {
            _http.Dispose();
        }
    }
}
