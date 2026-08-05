using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using VibeCheck.Core.Rules;

namespace VibeCheck.Core.DeepPass;

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
        _http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        _http.Timeout = TimeSpan.FromMinutes(5);

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", apiKey.Trim());
        }
    }

    /// <summary>
    /// Names the host as well as the model, because the reader is entitled to know where their
    /// source code was sent.
    /// </summary>
    /// <remarks>
    /// The deep pass uploads recovered source, and with a configurable endpoint the destination
    /// is a choice rather than a constant. A report that said only "an OpenAI-compatible
    /// endpoint" would be describing the one fact about this run that nobody can infer.
    /// </remarks>
    public string Description => $"an OpenAI-compatible endpoint at {_endpoint.Host} ({_model})";

    /// <summary>
    /// False. Some endpoints are free and some are local, and none of them can be priced from
    /// here, so no run through this backend is reported as money.
    /// </summary>
    public bool BillsTheReader => false;

    /// <inheritdoc/>
    public decimal? PriceOf(TokenUsage usage) => null;

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
            .PostAsJsonAsync(_endpoint, BuildBody(triaged, schema), cancellationToken)
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

        if (string.IsNullOrWhiteSpace(content))
        {
            return Failed(triaged, "the endpoint returned an empty answer", usage);
        }

        var answer = DeepPassPrompt.Parse(content, triaged);

        return new FileReview
        {
            Findings = answer.Findings,
            LowConfidenceDiscarded = answer.LowConfidenceDiscarded,
            Usage = usage,
        };
    }

    private object BuildBody(TriagedFile triaged, bool schema)
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
                new { role = "user", content = DeepPassPrompt.BuildPrompt(triaged) },
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
