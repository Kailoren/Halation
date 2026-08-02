using Anthropic;
using Anthropic.Models.Beta.Messages;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.DeepPass;

/// <summary>
/// What the API billed for.
/// </summary>
/// <remarks>
/// Cached tokens are counted separately because they are priced separately, and because
/// <c>input_tokens</c> reports only the uncached remainder. The system prompt here is cached on
/// every request, so a total built from <c>input_tokens</c> alone would report a fraction of both
/// the tokens sent and the money spent.
/// </remarks>
public sealed record TokenUsage
{
    public long Input { get; init; }

    public long Output { get; init; }

    /// <summary>Tokens written to the cache, billed at 1.25x the input rate.</summary>
    public long CacheWrite { get; init; }

    /// <summary>Tokens served from the cache, billed at 0.1x the input rate.</summary>
    public long CacheRead { get; init; }

    /// <summary>Everything the prompt contained, not just the part that missed the cache.</summary>
    public long TotalInput => Input + CacheWrite + CacheRead;

    /// <summary>Cost in US dollars at Claude Opus 5 rates, for the key holder who is paying it.</summary>
    public decimal EstimatedCost =>
        (Input / 1_000_000m * 5.00m)
        + (Output / 1_000_000m * 25.00m)
        + (CacheWrite / 1_000_000m * 6.25m)
        + (CacheRead / 1_000_000m * 0.50m);

    public static TokenUsage operator +(TokenUsage left, TokenUsage right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        return new TokenUsage
        {
            Input = left.Input + right.Input,
            Output = left.Output + right.Output,
            CacheWrite = left.CacheWrite + right.CacheWrite,
            CacheRead = left.CacheRead + right.CacheRead,
        };
    }
}

/// <summary>What one file's review produced.</summary>
public sealed record FileReview
{
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>Set when the file was not fully examined, and why.</summary>
    public string? Limitation { get; init; }

    public TokenUsage Usage { get; init; } = new();

    /// <summary>
    /// True when the requested model declined and a substitute answered instead. Reported,
    /// because a reader comparing two scans is entitled to know the review of one file came
    /// from somewhere else.
    /// </summary>
    public bool ServedByFallback { get; init; }
}

/// <summary>What a deep pass produced, including the reasons it produced nothing.</summary>
public sealed record DeepPassResult
{
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>Stated in the report, so an empty deep pass is never mistaken for a clean one.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    public int FilesExamined { get; init; }

    public TokenUsage Usage { get; init; } = new();

    /// <summary>
    /// What answered, in the words the report uses. Null when nothing did.
    /// </summary>
    public string? Backend { get; init; }

    /// <summary>Whether <see cref="EstimatedCost"/> describes money the reader was charged.</summary>
    /// <remarks>
    /// Defaults to true because the API backend was the only one for most of this type's life,
    /// and a new backend that spends something other than money has to say so deliberately.
    /// </remarks>
    public bool Billed { get; init; } = true;

    /// <summary>What these tokens are worth at published API rates, whoever ends up paying.</summary>
    public decimal EstimatedCost => Usage.EstimatedCost;

    /// <summary>
    /// What the reader was actually charged, or null when they were not charged at all.
    /// </summary>
    /// <remarks>
    /// A subscription-backed run consumes quota rather than money. The estimate above is still
    /// a true statement about the tokens, and still the wrong number to put in front of
    /// somebody as a bill, so the two are kept apart rather than conflated.
    /// </remarks>
    public decimal? BilledCost => Billed ? EstimatedCost : null;
}

/// <summary>
/// The reasoning half of the scan: reads recovered source and reports what pattern rules
/// cannot express.
/// </summary>
/// <remarks>
/// <para>
/// Everything here is advisory. Findings come back as <see cref="FindingSource.Assisted"/>,
/// which <c>ScoreCalculator</c> already refuses to let drive a do-not-install verdict: the
/// strongest claim in a report must not depend on whether the reader happened to supply an
/// API key.
/// </para>
/// <para>
/// Two API behaviours are load-bearing rather than incidental. Findings are requested as a
/// JSON schema, so the result is validated structure and not prose to be regex'd. And a
/// refusal is checked before the content is read: this model runs elevated cybersecurity
/// safeguards, a request reading like "find the vulnerabilities in this code" is squarely
/// what they watch for, and a decline arrives as a normal success response rather than an
/// error.
/// </para>
/// <para>
/// Because a decline is a realistic outcome here rather than a remote one, server-side
/// fallbacks are opted into: a policy decline is re-served by another model inside the same
/// call, so it costs a differently-sourced answer rather than the whole file. This is the
/// reason the request goes through the beta surface. <c>"default"</c> is used in preference to
/// naming a substitute, because the right substitute depends on why the request was declined,
/// and a named one would need revisiting every time that model is retired.
/// </para>
/// </remarks>
public sealed class DeepPassClient(string apiKey, string? model = null) : IDeepPassBackend
{
    private const string DefaultModel = "claude-opus-5";

    /// <summary>Room for thinking and the findings together: on this model both share the cap.</summary>
    private const int MaxTokens = 16_000;

    /// <summary>Gates the scalar <c>"default"</c> form of the fallback chain.</summary>
    private const string FallbackBeta = "server-side-fallback-2026-07-01";

    private readonly AnthropicClient _client = new() { ApiKey = apiKey };

    /// <inheritdoc/>
    public string Description => $"the Anthropic API ({model ?? DefaultModel})";

    /// <summary>True. Every token here is charged to the key the reader supplied.</summary>
    public bool BillsTheReader => true;

    /// <summary>
    /// Reviews one file. Returns an empty result rather than throwing, so a single failure
    /// costs one file's coverage instead of the whole pass.
    /// </summary>
    public async Task<FileReview> ReviewAsync(
        TriagedFile triaged,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        try
        {
            var response = await _client.Beta.Messages.Create(
                new MessageCreateParams
                {
                    Model = model ?? DefaultModel,
                    MaxTokens = MaxTokens,
                    Betas = [FallbackBeta],

                    // Re-serve a policy decline on a substitute model rather than losing the
                    // file. Reported afterwards, because the reader is owed the fact that a
                    // different model answered.
                    Fallbacks = new Default(),

                    // The system prompt is identical on every file, so it is marked cacheable.
                    // Measured, not assumed: at roughly 330 tokens it is under this model's
                    // 512-token minimum, so today the marker is inert and every file pays for
                    // the prompt in full. That is about a sixth of a cent per file, which is
                    // not worth padding the prompt to fix. The marker stays because it starts
                    // working on its own if the prompt grows past the minimum; the accounting
                    // below counts cached tokens either way, so the reported bill stays right
                    // whichever side of the line it lands on.
                    System = new List<BetaTextBlockParam>
                    {
                        new()
                        {
                            Text = DeepPassPrompt.SystemPrompt,
                            CacheControl = new BetaCacheControlEphemeral(),
                        },
                    },

                    // Medium: this is the reader's own money, and the task is reading one
                    // file rather than a long agentic loop.
                    OutputConfig = new BetaOutputConfig
                    {
                        Effort = Effort.Medium,
                        Format = new BetaJsonOutputFormat { Schema = DeepPassPrompt.FindingSchema },
                    },

                    Messages =
                    [
                        new() { Role = Role.User, Content = DeepPassPrompt.BuildPrompt(triaged) },
                    ],
                },
                cancellationToken).ConfigureAwait(false);

            // A declined request still reports the tokens it read, so usage is taken before the
            // early returns rather than after.
            var usage = Read(response.Usage);
            var servedByFallback = ServedByFallback(response);

            // Checked before the content is touched. A declined request is a successful
            // response with nothing in it, so reading content[0] first would throw. Reaching
            // here means every model in the chain declined, not just the first.
            if (response.StopReason == "refusal")
            {
                var category = response.StopDetails?.Category ?? "unspecified";
                return new FileReview
                {
                    Limitation = $"The deep pass was declined for {triaged.File.RelativePath} "
                                 + $"(policy category: {category}), so that file was not reviewed.",
                    Usage = usage,
                };
            }

            if (response.StopReason == "max_tokens")
            {
                return new FileReview
                {
                    Limitation = $"The review of {triaged.File.RelativePath} was cut off before it "
                                 + "finished, so that file was only partly examined.",
                    Usage = usage,
                    ServedByFallback = servedByFallback,
                };
            }

            var text = response.Content
                .Select(b => b.TryPickText(out var block) ? block.Text : null)
                .FirstOrDefault(t => t is not null);

            return text is null
                ? new FileReview
                {
                    Limitation = $"The deep pass returned nothing for {triaged.File.RelativePath}.",
                    Usage = usage,
                    ServedByFallback = servedByFallback,
                }
                : new FileReview
                {
                    Findings = DeepPassPrompt.Parse(text, triaged),
                    Usage = usage,
                    ServedByFallback = servedByFallback,
                };
        }
        catch (Anthropic.Exceptions.AnthropicRateLimitException)
        {
            return new FileReview
            {
                Limitation = "The deep pass was rate limited and stopped early. "
                             + "Findings below the point it stopped were not looked for.",
            };
        }
        catch (Anthropic.Exceptions.AnthropicApiException ex)
        {
            return new FileReview { Limitation = $"The deep pass failed: {ex.Message}" };
        }
    }

    private static TokenUsage Read(BetaUsage? usage) => usage is null
        ? new TokenUsage()
        : new TokenUsage
        {
            Input = usage.InputTokens,
            Output = usage.OutputTokens,
            CacheWrite = usage.CacheCreationInputTokens ?? 0,
            CacheRead = usage.CacheReadInputTokens ?? 0,
        };

    /// <summary>
    /// Whether a substitute model answered after the requested one declined. The API marks each
    /// switch with a block in the content, so this is read rather than inferred.
    /// </summary>
    private static bool ServedByFallback(BetaMessage response) =>
        response.Content.Any(b => b.TryPickFallback(out _));

    public void Dispose() => (_client as IDisposable)?.Dispose();
}
