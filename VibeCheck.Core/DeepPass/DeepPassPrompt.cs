using System.Text;
using System.Text.Json;

using VibeCheck.Core.Model;

namespace VibeCheck.Core.DeepPass;

/// <summary>
/// The question the deep pass asks, and how its answer is read back.
/// </summary>
/// <remarks>
/// <para>
/// Held apart from any one backend because more than one thing can answer it. A review that
/// came from a locally installed agent and a review that came from the API have to be the same
/// review: same instructions, same severity definitions, same shape of answer. If the prompt
/// lived inside one backend and the other paraphrased it, two scans of the same application
/// could differ for a reason that has nothing to do with the application.
/// </para>
/// <para>
/// The parsing is deliberately forgiving in one direction only. A malformed answer yields no
/// findings rather than throwing, because losing one file's coverage is better than losing the
/// scan. It never invents a finding to fill a gap.
/// </para>
/// </remarks>
public static class DeepPassPrompt
{
    /// <summary>
    /// The schema findings must satisfy. Constrained output rather than parsed prose, so a
    /// malformed answer is impossible instead of merely unlikely.
    /// </summary>
    public static IReadOnlyDictionary<string, JsonElement> FindingSchema { get; } =
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
                            user_severity = new { type = "string", @enum = new[] { "none", "low", "medium", "high", "critical" } },
                            user_impact = new { type = "string" },
                            file = new { type = "string" },
                            evidence = new { type = "string" },
                            reachability = new { type = "string" },
                            why_rules_miss_it = new { type = "string" },
                            remediation = new { type = "string" },
                            confidence = new { type = "string", @enum = new[] { "low", "medium", "high" } },
                        },
                        required = new[]
                        {
                            "title", "severity", "user_severity", "user_impact", "file",
                            "evidence", "reachability", "why_rules_miss_it", "remediation",
                            "confidence",
                        },
                        additionalProperties = false,
                    },
                },
            }),
            ["required"] = JsonSerializer.SerializeToElement(new[] { "findings" }),
            ["additionalProperties"] = JsonSerializer.SerializeToElement(false),
        };

    public const string SystemPrompt =
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

        Every finding is read by two people, and they are not asking the same question. Judge
        both, separately:

        - severity: how bad this is for whoever ships the application.
        - user_severity: how bad this is for somebody who merely runs it, having not written
          it and being unable to change it. Use "none" when it genuinely does not touch them.
          A leaked credential belonging to the author is usually "none" or "low" for this
          reader; something that lets a file or a web response run code on their machine is
          usually higher here than it is for the developer.
        - user_impact: that same finding written for that reader, in plain language. No rule
          names, no CWE or CVE numbers, no jargon. Say what it could mean for them, and say
          plainly when the honest answer is that this is the author's problem and not theirs.

        Rules for what you report:
        - Only report what the code you were shown demonstrates. If reachability depends on a
          file you cannot see, say so in the reachability field rather than assuming either way.
        - Report nothing rather than pad. An empty findings array is a valid and useful answer.
        - Set confidence honestly. "high" means the code in front of you proves it.
        """;

    /// <summary>
    /// The file, why it was chosen, and what the pattern scanner already said about it.
    /// </summary>
    public static string BuildPrompt(TriagedFile triaged)
    {
        ArgumentNullException.ThrowIfNull(triaged);

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

    /// <summary>
    /// Reads the findings out of a reply. Returns none rather than throwing: a backend that
    /// answered badly costs one file's coverage, not the scan.
    /// </summary>
    public static IReadOnlyList<Finding> Parse(string json, TriagedFile triaged)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        var findings = new List<Finding>();

        if (string.IsNullOrWhiteSpace(json))
        {
            return findings;
        }

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
                if (ReadFinding(element, triaged) is { } finding)
                {
                    findings.Add(finding);
                }
            }
        }
        catch (JsonException)
        {
            // Constrained output makes this near-impossible on the API backend, but a backend
            // that cannot constrain its output can produce anything at all, and a malformed
            // answer must not take the scan down.
        }

        return findings;
    }

    private static Finding? ReadFinding(JsonElement element, TriagedFile triaged)
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

            // Asked for rather than derived. The model has read the file and can tell whether
            // a finding reaches the person running the application; a local rule mapping one
            // severity onto the other would be guessing from strictly less information.
            UserSeverity = ParseSeverity(Text("user_severity")),
            Category = FindingCategory.CodeSafety,

            // The whole point of the pass: never a rule finding, so it can never block.
            Source = FindingSource.Assisted,

            Description =
                $"{Text("why_rules_miss_it")}\n\nReachability: {Text("reachability")}"
                + $"\n\nConfidence: {confidence}.",
            UserDescription = Text("user_impact")
                ?? "This was identified by the AI deep pass, which did not describe what it "
                   + "means for someone running the application.",
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
        "none" => Severity.Info,
        _ => Severity.Medium,
    };
}
