using System.Text;
using System.Text.Json;

using Halation.Core.Model;
using Halation.Core.Rules;

namespace Halation.Core.DeepPass;

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
/// <summary>What one reply contained, including what was thrown away reading it.</summary>
public sealed record DeepPassAnswer
{
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>
    /// Findings the model marked low confidence, which are not shown. Counted so the report
    /// can say they existed rather than leaving their absence to look like a clean file.
    /// </summary>
    public int LowConfidenceDiscarded { get; init; }

    /// <summary>
    /// Capabilities the file's own comments explain, and the reason given.
    /// </summary>
    /// <remarks>
    /// A prefill for the question, never an answer to it: the text came out of the artifact
    /// being examined. See <see cref="PurposeSource.SourceComment"/>. Normally empty, and always
    /// empty for decompiled code, where the comments no longer exist.
    /// </remarks>
    public IReadOnlyDictionary<Capability, string> Explains { get; init; } =
        new Dictionary<Capability, string>();
}

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

                            // Asked for because the code arrives numbered and the answer is
                            // resolved against this application's own copy of the file. A
                            // description rather than a bare type: an unlabelled field called
                            // "evidence" was being filled with prose about the file, which then
                            // reached the reader inside a code fence looking like their own code.
                            line = new
                            {
                                type = "integer",
                                description = "The line number, from the numbers printed to the "
                                    + "left of the code, where the problem is. Required, and it "
                                    + "must be the line the quotation below is taken from.",
                            },
                            evidence = new
                            {
                                type = "string",
                                description = "The code at that line, copied exactly as it "
                                    + "appears, without the line number. Copy it; do not "
                                    + "describe it, summarise it, or write a sentence about it.",
                            },
                            reachability = new { type = "string" },
                            why_rules_miss_it = new { type = "string" },
                            remediation = new { type = "string" },
                            confidence = new { type = "string", @enum = new[] { "low", "medium", "high" } },
                        },
                        required = new[]
                        {
                            "title", "severity", "user_severity", "user_impact", "file", "line",
                            "evidence", "reachability", "why_rules_miss_it", "remediation",
                            "confidence",
                        },
                        additionalProperties = false,
                    },
                },
                // What the author already said about a capability, so the reader is asked to
                // confirm their own note rather than retype it. Never an answer: it ships inside
                // the artifact. See PurposeSource.SourceComment.
                explains = new
                {
                    type = "array",
                    items = new
                    {
                        type = "object",
                        properties = new
                        {
                            capability = new
                            {
                                type = "string",
                                @enum = Enum.GetNames<Capability>(),
                            },
                            reason = new { type = "string" },
                        },
                        required = new[] { "capability", "reason" },
                        additionalProperties = false,
                    },
                },
            }),

            // Both listed: a strict schema with additionalProperties false requires every
            // declared property to be required, and an empty array is the normal answer.
            ["required"] = JsonSerializer.SerializeToElement(new[] { "findings", "explains" }),
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

        Separately from findings, fill "explains". Some code does something that looks alarming
        out of context and the author has already written down why, in a comment or a docstring
        beside it. When this file both does one of the named things and says why, record the
        capability and the author's own words.

        - The reason must be copied from the file, word for word. Do not paraphrase it, do not
          summarise it and do not write your own sentence. It is checked against the file, and
          anything that is not in there is discarded.
        - It must be the author explaining their own code, not you describing it. "Clears stale
          sessions left behind by the browser" is a reason. "This reads browser cookies" is a
          description, and "this could be used to steal credentials" is a finding. Neither of the
          last two belongs here.
        - This is not a finding and not an endorsement. It is repeated back to the person running
          the scan so they can confirm or reject it, because a comment ships inside the
          application and cannot vouch for it.
        - An empty array is the normal answer, and is expected for decompiled code, where the
          comments no longer exist. Leave it empty rather than filling it with something you
          worked out yourself.

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

        // Numbered, and said out loud rather than left to be inferred from the gutter. The
        // numbers are the only way back from an answer to a place in the file.
        prompt.AppendLine("The code is printed with a line number and a bar before each line.");
        prompt.AppendLine("Those numbers are not part of the file. Cite them.");
        prompt.AppendLine();
        prompt.AppendLine("```");
        prompt.AppendLine(DeepPassTriage.NumberedExcerpt(triaged.File));
        prompt.AppendLine("```");

        return prompt.ToString();
    }

    /// <summary>
    /// Reads the findings out of a reply. Returns none rather than throwing: a backend that
    /// answered badly costs one file's coverage, not the scan.
    /// </summary>
    /// <remarks>
    /// Findings the model marked low confidence are discarded here rather than printed with a
    /// warning attached. A hedge repeated on every item stops being read, and a report full of
    /// things that might not be true is worth less than a shorter one where each entry is
    /// backed by the code it quotes. The count of what was dropped is carried out rather than
    /// swallowed, because "we found nothing else" and "we found things we did not trust enough
    /// to show you" are different statements and the reader is owed the right one.
    /// </remarks>
    public static DeepPassAnswer Parse(string json, TriagedFile triaged)
    {
        ArgumentNullException.ThrowIfNull(triaged);

        var findings = new List<Finding>();
        var explains = new Dictionary<Capability, string>();
        var discarded = 0;

        if (string.IsNullOrWhiteSpace(json))
        {
            return new DeepPassAnswer();
        }

        try
        {
            using var document = JsonDocument.Parse(json);

            // Read independently of each other. A model that answered one half and fumbled the
            // other should lose only that half; returning early on a missing findings array
            // would also throw away explanations that arrived beside it.
            if (document.RootElement.TryGetProperty("findings", out var array)
                && array.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in array.EnumerateArray())
                {
                    if (IsLowConfidence(element))
                    {
                        discarded++;
                        continue;
                    }

                    if (ReadFinding(element, triaged) is { } finding)
                    {
                        findings.Add(finding);
                    }
                }
            }

            ReadExplanations(document.RootElement, triaged.File.Content, explains);
        }
        catch (JsonException)
        {
            // Constrained output makes this near-impossible on the API backend, but a backend
            // that cannot constrain its output can produce anything at all, and a malformed
            // answer must not take the scan down.
        }

        return new DeepPassAnswer
        {
            Findings = findings,
            LowConfidenceDiscarded = discarded,
            Explains = explains,
        };
    }

    /// <summary>
    /// Reads the author's own stated reasons, keeping only the ones the file actually contains.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bounded and scrubbed like every other string that comes back from a model which has just
    /// read a file this scanner assumes is hostile. Only the seven named capabilities are
    /// accepted, because this text is put in front of a reader as something their own
    /// application said about itself.
    /// </para>
    /// <para>
    /// <b>And the quote must be in the file, checked here rather than asked for and trusted.</b>
    /// The first real run of this feature, qwen2.5-coder:7b over FleetFinder's source, returned
    /// three explanations and <i>none of them appeared anywhere in the source</i>. They were the
    /// model's own accusations wearing the author's voice: one claimed a reason for reading
    /// browser cookies in an application whose source does not contain the word "cookie". Shown
    /// as "The code says why", that is the scanner inventing a note and attributing it to the
    /// person being scanned, which is worse than not having the feature.
    /// </para>
    /// <para>
    /// So a paraphrase is no longer good enough and the prompt no longer asks for one. Anything
    /// that cannot be found in the file it was supposedly read from is dropped. Whitespace is
    /// normalised before comparing, because a quote spanning a wrapped comment arrives with the
    /// line breaks and leading slashes flattened out of it, and that is a formatting difference
    /// rather than a different sentence.
    /// </para>
    /// </remarks>
    private static void ReadExplanations(
        JsonElement root, string content, Dictionary<Capability, string> into)
    {
        if (!root.TryGetProperty("explains", out var array)
            || array.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        var haystack = Normalise(content);

        foreach (var element in array.EnumerateArray())
        {
            if (!element.TryGetProperty("capability", out var name)
                || !Enum.TryParse<Capability>(name.GetString(), ignoreCase: true, out var capability))
            {
                continue;
            }

            var reason = Redaction.Flatten(
                element.TryGetProperty("reason", out var text) ? text.GetString() : null,
                Redaction.MaxProse);

            if (string.IsNullOrWhiteSpace(reason) || !Quoted(haystack, reason))
            {
                continue;
            }

            // First answer wins. A model repeating itself across files should not have the
            // second mention quietly replace the first.
            into.TryAdd(capability, reason);
        }
    }

    /// <summary>
    /// Whether the model's quote really is in the file it read.
    /// </summary>
    /// <remarks>
    /// A floor on length as well, because a three-word fragment appears in almost any file by
    /// accident and would let a fabricated reason through on a coincidence.
    /// </remarks>
    private static bool Quoted(string normalisedContent, string reason)
    {
        var needle = Normalise(reason).Trim(' ', '.', ',', '"', '\'');

        return needle.Length >= 20
               && normalisedContent.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Collapses whitespace and comment punctuation so a wrapped quote still matches.</summary>
    private static string Normalise(string text)
    {
        var builder = new StringBuilder(text.Length);
        var space = false;

        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c) || c is '/' or '*' or '#')
            {
                space = true;
                continue;
            }

            if (space && builder.Length > 0)
            {
                builder.Append(' ');
            }

            space = false;
            builder.Append(c);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Whether the model said outright that the code did not convince it.
    /// </summary>
    /// <remarks>
    /// Only an explicit "low" is dropped. A missing or unrecognised value is kept, because the
    /// absence of a confidence claim is not a confession of doubt, and silently discarding on
    /// a field the model failed to fill would quietly shrink coverage for a formatting reason.
    /// </remarks>
    private static bool IsLowConfidence(JsonElement element) =>
        element.TryGetProperty("confidence", out var confidence)
        && confidence.ValueKind == JsonValueKind.String
        && string.Equals(confidence.GetString(), "low", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads one finding out of the model's answer.
    /// </summary>
    /// <remarks>
    /// Every string here is derived from the scanned application's own source and is therefore
    /// attacker-controlled, so each one is flattened on the way in rather than trusted to be
    /// prose. See <see cref="Redaction.Flatten"/> for what a title containing two newlines was
    /// able to do to an exported report.
    /// </remarks>
    private static Finding? ReadFinding(JsonElement element, TriagedFile triaged)
    {
        if (!element.TryGetProperty("title", out var title)
            || Redaction.Flatten(title.GetString(), max: 160) is not { Length: > 0 } titleText)
        {
            return null;
        }

        // Prose by default. Everything read here except the title and the path is an
        // explanation the reader is meant to finish, and the old 400-character default was a
        // label's budget: it stopped each one mid-sentence, in the part of the report that
        // exists precisely because a pattern match could not say this much.
        string? Text(string name, int max = Redaction.MaxProse) => Redaction.Flatten(
            element.TryGetProperty(name, out var value) ? value.GetString() : null, max);

        var confidence = Text("confidence") ?? "medium";

        // The quotation is taken from the file this application already holds, using the line
        // the model cited, rather than from whatever the model typed into the evidence field.
        // See EvidenceLocator: the model's own text is a fallback for finding the place, never
        // the thing printed. A quotation the reader cannot find in their own file is the one
        // failure a code fence actively conceals.
        var located = EvidenceLocator.Locate(
            triaged.File.Content,
            element.TryGetProperty("line", out var lineElement)
                && lineElement.ValueKind == JsonValueKind.Number
                && lineElement.TryGetInt32(out var claimed)
                    ? claimed
                    : null,
            Text("evidence"));

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
            // Through the same masking every rule finding's evidence goes through, which caps
            // the length and leaves nothing that could close the code fence it is printed in.
            Evidence = located.Evidence is { } quoted
                ? Redaction.BuildEvidence(quoted)
                : null,
            Remediation = Text("remediation"),

            // The file this request was about, never the one the answer names. Each call carries
            // exactly one file, so the model's own "file" field can agree or be wrong and there
            // is nothing it can add. It was wrong on a real run, returning a bare name for a
            // file two directories down, which prints a location nobody can open. Now that the
            // line comes from this application, the path has to as well, or half of a citation
            // is trustworthy and the reader cannot tell which half.
            FilePath = triaged.File.RelativePath,

            // Only ever a line this application resolved itself, so "Location" cannot name a
            // place that does not exist.
            Line = located.Line,
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
