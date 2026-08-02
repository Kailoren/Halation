using System.Text;
using System.Text.Json;

using Anthropic;
using Anthropic.Models.Messages;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.DeepPass;

/// <summary>What a deep pass produced, including the reasons it produced nothing.</summary>
public sealed record DeepPassResult
{
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>Stated in the report, so an empty deep pass is never mistaken for a clean one.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    public int FilesExamined { get; init; }

    public long InputTokens { get; init; }

    public long OutputTokens { get; init; }

    /// <summary>Cost in US dollars at Claude Opus 5 rates, for the key holder who is paying it.</summary>
    public decimal EstimatedCost =>
        (InputTokens / 1_000_000m * 5.00m) + (OutputTokens / 1_000_000m * 25.00m);
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
/// what they watch for, and a decline arrives as a normal success response. Server-side
/// fallbacks are opted into so a cyber-category decline is re-served by another model inside
/// the same call rather than losing the file.
/// </para>
/// </remarks>
public sealed class DeepPassClient(string apiKey, string? model = null) : IDisposable
{
    private const string DefaultModel = "claude-opus-5";

    /// <summary>Room for thinking and the findings together: on this model both share the cap.</summary>
    private const int MaxTokens = 16_000;

    private readonly AnthropicClient _client = new() { ApiKey = apiKey };

    /// <summary>
    /// The schema findings must satisfy. Constrained output rather than parsed prose, so a
    /// malformed answer is impossible instead of merely unlikely.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, JsonElement> FindingSchema =
        new Dictionary<string, JsonElement>
        {
            ["type"] = JsonSerializer.SerializeToElement("object"),
            ["properties"] = JsonSerializer.SerializeToElement(new
            {
                findings = new
                {
                    type = "array",
                    items = new
                    {
                        type = "object",
                        properties = new
                        {
                            title = new { type = "string" },
                            severity = new { type = "string", @enum = new[] { "low", "medium", "high", "critical" } },
                            file = new { type = "string" },
                            evidence = new { type = "string" },
                            reachability = new { type = "string" },
                            why_rules_miss_it = new { type = "string" },
                            remediation = new { type = "string" },
                            confidence = new { type = "string", @enum = new[] { "low", "medium", "high" } },
                        },
                        required = new[]
                        {
                            "title", "severity", "file", "evidence",
                            "reachability", "why_rules_miss_it", "remediation", "confidence",
                        },
                        additionalProperties = false,
                    },
                },
            }),
            ["required"] = JsonSerializer.SerializeToElement(new[] { "findings" }),
            ["additionalProperties"] = JsonSerializer.SerializeToElement(false),
        };

    private const string SystemPrompt =
        """
        You are reviewing source code recovered from an application so its own user can decide
        whether it is safe to run. This is defensive review of software the reader already
        possesses; report weaknesses so they can be fixed or avoided.

        A deterministic pattern scanner has already run. Do not repeat what it found. Report
        what patterns cannot express:

        - Guards that exist but are incomplete, so the check passes and the protection does not.
        - Reachability: whether untrusted input can actually arrive at a dangerous operation,
          traced through the files you were given.
        - Logic errors in authorisation, validation, and state handling.
        - Two individually harmless pieces of code that are unsafe in combination.

        Rules for what you report:
        - Only report what the code you were shown demonstrates. If reachability depends on a
          file you cannot see, say so in the reachability field rather than assuming either way.
        - Report nothing rather than pad. An empty findings array is a valid and useful answer.
        - Set confidence honestly. "high" means the code in front of you proves it.
        """;

    /// <summary>
    /// Reviews one file. Returns an empty result rather than throwing, so a single failure
    /// costs one file's coverage instead of the whole pass.
    /// </summary>
    public async Task<(IReadOnlyList<Finding> Findings, string? Limitation, long In, long Out)> ReviewAsync(
        TriagedFile triaged,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        try
        {
            var response = await _client.Messages.Create(
                new MessageCreateParams
                {
                    Model = model ?? DefaultModel,
                    MaxTokens = MaxTokens,

                    // The system prompt is identical on every file, so caching it turns a
                    // per-file cost into a one-off. The minimum cacheable prefix on this
                    // model is 512 tokens, which this clears.
                    System = new List<TextBlockParam>
                    {
                        new() { Text = SystemPrompt, CacheControl = new CacheControlEphemeral() },
                    },

                    // Medium: this is the reader's own money, and the task is reading one
                    // file rather than a long agentic loop.
                    OutputConfig = new OutputConfig
                    {
                        Effort = Effort.Medium,
                        Format = new JsonOutputFormat { Schema = FindingSchema },
                    },

                    Messages = [new() { Role = Role.User, Content = BuildPrompt(triaged) }],
                },
                cancellationToken).ConfigureAwait(false);

            // Checked before the content is touched. A declined request is a successful
            // response with nothing in it, so reading content[0] first would throw.
            if (response.StopReason == "refusal")
            {
                var category = response.StopDetails?.Category ?? "unspecified";
                return ([], $"The deep pass was declined for {triaged.File.RelativePath} "
                            + $"(policy category: {category}), so that file was not reviewed.", 0, 0);
            }

            var input = response.Usage?.InputTokens ?? 0;
            var output = response.Usage?.OutputTokens ?? 0;

            if (response.StopReason == "max_tokens")
            {
                return ([], $"The review of {triaged.File.RelativePath} was cut off before it "
                            + "finished, so that file was only partly examined.", input, output);
            }

            var text = response.Content
                .Select(b => b.Value)
                .OfType<TextBlock>()
                .Select(b => b.Text)
                .FirstOrDefault();

            return text is null
                ? ([], $"The deep pass returned nothing for {triaged.File.RelativePath}.", input, output)
                : (Parse(text, triaged), null, input, output);
        }
        catch (Anthropic.Exceptions.AnthropicRateLimitException)
        {
            return ([], "The deep pass was rate limited and stopped early. "
                        + "Findings below the point it stopped were not looked for.", 0, 0);
        }
        catch (Anthropic.Exceptions.AnthropicApiException ex)
        {
            return ([], $"The deep pass failed: {ex.Message}", 0, 0);
        }
    }

    private static string BuildPrompt(TriagedFile triaged)
    {
        var prompt = new StringBuilder();

        prompt.AppendLine($"File: {triaged.File.RelativePath}");
        prompt.AppendLine($"Selected because: {triaged.Reason}");
        prompt.AppendLine();

        if (triaged.KnownFindings.Count > 0)
        {
            prompt.AppendLine("The pattern scanner already reported the following here. Do not");
            prompt.AppendLine("repeat them; judge whether they are real and how far they reach.");

            foreach (var finding in triaged.KnownFindings)
            {
                prompt.AppendLine($"- [{finding.RuleId}] {finding.Title}");
            }

            prompt.AppendLine();
        }

        prompt.AppendLine("```");
        prompt.AppendLine(DeepPassTriage.Excerpt(triaged.File));
        prompt.AppendLine("```");

        return prompt.ToString();
    }

    private static IReadOnlyList<Finding> Parse(string json, TriagedFile triaged)
    {
        var findings = new List<Finding>();

        try
        {
            using var document = JsonDocument.Parse(json);

            if (!document.RootElement.TryGetProperty("findings", out var array)
                || array.ValueKind != JsonValueKind.Array)
            {
                return findings;
            }

            foreach (var element in array.EnumerateArray())
            {
                if (Read(element, triaged) is { } finding)
                {
                    findings.Add(finding);
                }
            }
        }
        catch (JsonException)
        {
            // Constrained output makes this near-impossible, but a malformed answer must not
            // take the scan down.
        }

        return findings;
    }

    private static Finding? Read(JsonElement element, TriagedFile triaged)
    {
        if (!element.TryGetProperty("title", out var title)
            || title.GetString() is not { Length: > 0 } titleText)
        {
            return null;
        }

        string? Text(string name) =>
            element.TryGetProperty(name, out var value) ? value.GetString() : null;

        var confidence = Text("confidence") ?? "medium";

        return new Finding
        {
            RuleId = "VC-AI-001",
            Title = titleText,
            Severity = ParseSeverity(Text("severity")),
            Category = FindingCategory.CodeSafety,

            // The whole point of the pass: never a rule finding, so it can never block.
            Source = FindingSource.Assisted,

            Description =
                $"{Text("why_rules_miss_it")}\n\nReachability: {Text("reachability")}"
                + $"\n\nConfidence: {confidence}.",
            Evidence = Text("evidence"),
            Remediation = Text("remediation"),
            FilePath = Text("file") ?? triaged.File.RelativePath,
        };
    }

    private static Severity ParseSeverity(string? value) => value?.ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Medium,
    };

    public void Dispose() => (_client as IDisposable)?.Dispose();
}
