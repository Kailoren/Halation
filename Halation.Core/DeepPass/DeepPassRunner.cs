using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.DeepPass;

/// <summary>
/// Runs the deep pass over the triaged files and collects what it found.
/// </summary>
/// <remarks>
/// Files are reviewed one at a time rather than concatenated into a single request. A file
/// the safety classifiers decline then costs at most that one file rather than the whole pass,
/// which matters here more than elsewhere: the request is asking about security weaknesses
/// in recovered code, and that is exactly the shape those classifiers watch for. Usually it
/// costs nothing at all, because the client falls back to a substitute model; the count of
/// files that took that route is reported rather than absorbed.
/// </remarks>
public static class DeepPassRunner
{
    /// <summary>A backend to use, or the reason there is not one.</summary>
    private readonly record struct BackendChoice(IDeepPassBackend? Backend, string? Problem);

    public static async Task<DeepPassResult> RunAsync(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<Finding> deterministicFindings,
        ScanOptions options,
        IDeepPassBackend? backend = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(deterministicFindings);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.DeepPassEnabled)
        {
            return new DeepPassResult();
        }

        // A caller-supplied backend belongs to the caller, including its lifetime.
        var supplied = backend is not null;
        var chosen = supplied
            ? new BackendChoice(backend, null)
            : await ChooseAsync(options, cancellationToken).ConfigureAwait(false);

        if (chosen.Backend is not { } client)
        {
            // Nothing could answer. Said out loud rather than returning an empty result, which
            // would be indistinguishable from a deep pass that ran and found nothing.
            return new DeepPassResult
            {
                Outcome = DeepPassOutcome.NotRun,
                Limitations = [chosen.Problem!],
            };
        }

        try
        {
            return await ReviewAllAsync(
                files, deterministicFindings, options, client, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (!supplied)
            {
                client.Dispose();
            }
        }
    }

    private static async Task<DeepPassResult> ReviewAllAsync(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<Finding> deterministicFindings,
        ScanOptions options,
        IDeepPassBackend client,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var triage = DeepPassTriage.Triage(files, deterministicFindings, options.DeepPassMaxFiles);
        var triaged = triage.Selected;

        if (triaged.Count == 0)
        {
            // Nothing was read, so nothing may be claimed, and that includes a claim about the
            // files themselves. All triage found was that none of them had a finding or used a
            // call on its list, which is a fact about the list as much as about the code.
            List<string> said =
            [
                "The deep pass ran but had nothing to read. It reads files a check flagged and "
                + "files outside the tests that use one of a list of calls that bring in data "
                + "from outside the application, and there were none of either here. The list "
                + "goes by the names of calls in the code, so it cannot say whether outside data "
                + "reaches this application some other way.",
            ];

            if (triage.LanguagesWithoutPatterns.Count > 0)
            {
                said.Add(Unpatterned(triage.LanguagesWithoutPatterns));
            }

            return new DeepPassResult
            {
                Outcome = DeepPassOutcome.NotRun,
                Backend = client.Description,
                Billed = client.BillsTheReader,
                SpendsSubscription = client.SpendsSubscription,
                Limitations = said,
            };
        }

        var plan = DeepPassPlan.Build(files, triaged, options.DeepPassMaxRequests);
        var findings = new List<Finding>();
        var limitations = new List<string>();
        var usage = new TokenUsage();
        var explains = new Dictionary<Capability, string>();
        var tallies = plan.Files.ToDictionary(
            f => f.Triaged.File.RelativePath,
            f => new Tally { Planned = f.Requests.Count, Total = f.Total },
            StringComparer.Ordinal);

        var sent = 0;
        var fellBack = 0;
        var discarded = 0;
        var stopped = false;

        foreach (var chunk in plan.Requests)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Counter first, path last. The count is the part that says how much is left and
            // it is the same length every time; the path is the part that varies without
            // bound, so anything the label cannot fit comes off the end of the path rather
            // than off the progress.
            var part = chunk.Of > 1 ? $" ({chunk.Index}/{chunk.Of})" : string.Empty;

            progress?.Report(new ScanProgress(
                ScanStage.DeepPass,
                $"Deep pass {sent + 1} of {plan.Requests.Count}: "
                + ForProgress(chunk.File.RelativePath) + part,
                (int)((sent + 1) / (double)plan.Requests.Count * 100)));

            var review = await client.ReviewAsync(chunk, cancellationToken).ConfigureAwait(false);
            var tally = tallies[chunk.File.RelativePath];

            findings.AddRange(review.Findings);
            usage += review.Usage;
            discarded += review.LowConfidenceDiscarded;
            sent++;
            tally.Attempted++;

            switch (review.Outcome)
            {
                case ReviewOutcome.Reviewed:
                    tally.Reviewed++;
                    tally.CharsReviewed += chunk.Chars;
                    break;

                case ReviewOutcome.Partly:
                    tally.Partly++;
                    break;

                default:
                    tally.Failed++;
                    break;
            }

            // First file to explain a capability wins, so a reason quoted where the thing is
            // actually done is not replaced by a passing mention somewhere else.
            foreach (var (capability, reason) in review.Explains)
            {
                explains.TryAdd(capability, reason);
            }

            if (review.ServedByFallback)
            {
                fellBack++;
            }

            if (review.Limitation is not null)
            {
                limitations.Add(review.Limitation);
            }

            if (review.StopsPass)
            {
                stopped = true;
                break;
            }
        }

        var reviewed = tallies.Values.Count(t => t.Whole);
        var partly = tallies.Values.Count(t => !t.Whole && (t.Reviewed > 0 || t.Partly > 0));
        var failed = tallies.Values.Count(t => t.Attempted > 0 && t.Reviewed == 0 && t.Partly == 0);
        var untouched = tallies.Values.Count(t => t.Attempted == 0);
        var charsReviewed = tallies.Values.Sum(t => t.CharsReviewed);
        var coverage = Percent(charsReviewed, plan.CodeChars);

        var outcome = (reviewed + partly) switch
        {
            0 when sent == 0 => DeepPassOutcome.NotRun,
            0 => DeepPassOutcome.Failed,
            _ when reviewed == tallies.Count && !triage.HitCeiling => DeepPassOutcome.Reviewed,
            _ => DeepPassOutcome.PartlyReviewed,
        };

        limitations.InsertRange(0, Describe(
            outcome, client, files.Count, plan, triage,
            reviewed, partly, failed, untouched, sent, coverage, stopped));

        // Stated once, here, rather than repeated on every finding. A hedge attached to each
        // item stops being read and starts reading as a tool that does not trust its own
        // output.
        if (outcome is DeepPassOutcome.Reviewed or DeepPassOutcome.PartlyReviewed)
        {
            limitations.Add(
                "Deep pass findings are inferred by a language model rather than matched by a "
                + "rule. Each one quotes the code it is based on so it can be checked, and none "
                + "of them can trigger a do-not-install verdict.");
        }

        // What was withheld. Without this line a file whose findings were all dropped looks
        // identical to a file the model had nothing to say about.
        if (discarded > 0)
        {
            limitations.Add(
                $"{discarded} further observation{(discarded == 1 ? " was" : "s were")} not "
                + "shown, because the model marked "
                + (discarded == 1 ? "it" : "them")
                + " low confidence: the code it read did not demonstrate the problem.");
        }

        // Not hidden. Two scans of the same application can now disagree because different
        // models answered, and a reader comparing them should be told that rather than left
        // to wonder.
        if (fellBack > 0)
        {
            limitations.Add(
                $"{fellBack} of the {sent} requests were declined by the requested model on "
                + "policy grounds and answered by a substitute model instead. Those reviews are "
                + "not directly comparable with the rest.");
        }

        return new DeepPassResult
        {
            Findings = findings,
            Limitations = limitations,
            Outcome = outcome,
            FilesSelected = tallies.Count,
            FilesReviewed = reviewed,
            FilesPartlyReviewed = partly,
            FilesFailed = failed,
            FilesNotAttempted = untouched,
            Requests = sent,
            CodeReviewedPercent = sent == 0 ? null : coverage,
            Vendored = plan.Vendored,
            Explains = explains,
            Usage = usage,
            Backend = client.Description,
            Billed = client.BillsTheReader,
            SpendsSubscription = client.SpendsSubscription,

            // Asked of whatever answered. A backend pointed at an endpoint it did not choose
            // returns null here, and the report then says how many tokens were spent rather
            // than inventing what they were worth.
            EstimatedCost = client.PriceOf(usage),
        };
    }

    /// <summary>How one file fared, counted in requests rather than assumed from the file.</summary>
    private sealed class Tally
    {
        public int Planned { get; init; }

        public int Total { get; init; }

        public int Attempted { get; set; }

        public int Reviewed { get; set; }

        public int Partly { get; set; }

        public int Failed { get; set; }

        public long CharsReviewed { get; set; }

        /// <summary>Whether every part of this file's own code was read and answered for.</summary>
        public bool Whole => Planned == Total && Reviewed == Total && Total > 0;
    }

    /// <summary>
    /// The sentences that say what the pass did, written from what happened rather than from
    /// what was asked for.
    /// </summary>
    /// <remarks>
    /// This is the fix for the report that described a pass where every single request had
    /// failed as one where the files "were also read a second time by the AI", named the thing
    /// that had "answered" it, and put its findings in the footer, all with zero tokens spent.
    /// Each branch below states one of the outcomes and none of them states another's.
    /// </remarks>
    private static List<string> Describe(
        DeepPassOutcome outcome,
        IDeepPassBackend client,
        int fileCount,
        DeepPassPlan plan,
        TriageResult triage,
        int reviewed,
        int partly,
        int failed,
        int untouched,
        int sent,
        int coverage,
        bool stopped)
    {
        var lines = new List<string>();

        if (outcome == DeepPassOutcome.NotRun)
        {
            lines.Add(
                $"The deep pass did not run: nothing was sent to {client.Description}, so no "
                + "finding below comes from it.");

            return lines;
        }

        if (outcome == DeepPassOutcome.Failed)
        {
            lines.Add(
                $"The deep pass did not review anything. All {sent} request"
                + $"{(sent == 1 ? "" : "s")} to {client.Description} failed, so no finding below "
                + "comes from it and the reasons are listed here rather than counted as reading.");

            return lines;
        }

        // Which thing answered. Two backends run different models under different settings, so
        // a reader comparing two reports of the same application is owed this before they start
        // wondering why the findings differ.
        lines.Add($"The deep pass was answered by {client.Description}.");

        // Every recovered file went through the rule pass; this is the second read of the
        // subset triage picked, and the two must not be confused.
        var second = outcome == DeepPassOutcome.Reviewed
            ? $"{reviewed} of them {(reviewed == 1 ? "was" : "were")} also read a second time by "
              + $"the AI, in {sent} request{(sent == 1 ? "" : "s")}."
            : $"The AI read part of it as well: {reviewed} file"
              + $"{(reviewed == 1 ? "" : "s")} in full, {partly} in part, {failed} it could not "
              + $"read at all, and {untouched} it did not reach.";

        lines.Add(
            $"Every one of the {fileCount:N0} files in this application was checked. {second} "
            + Selection(fileCount, triage));

        if (triage.LanguagesWithoutPatterns.Count > 0)
        {
            lines.Add(Unpatterned(triage.LanguagesWithoutPatterns));
        }

        // The deep pass's own coverage, which is not the coverage figure beside the score: that
        // one says how much of the application could be read at all, and this one says how much
        // of it the model was actually shown.
        lines.Add(
            $"The AI read {coverage}% of this application's recovered code. The rest of the "
            + "score and every finding not marked as inferred comes from the checks, which ran "
            + "over all of it.");

        if (triage.HitCeiling)
        {
            lines.Add(
                $"{triage.Qualified:N0} files were picked for a second reading and the file limit "
                + $"stopped the pass at {triage.Selected.Count}, so "
                + $"{triage.Qualified - triage.Selected.Count:N0} of them did not get one. Raising "
                + "the limit would cover them.");
        }

        if (plan.HitRequestCeiling)
        {
            lines.Add(
                $"The pass reached its limit of {plan.Requests.Count} requests. Large files are "
                + "read a piece at a time, and the pieces past that limit were not sent: "
                + $"{plan.PartialFiles} file{(plan.PartialFiles == 1 ? " was" : "s were")} read "
                + $"in part and {plan.UnreadFiles} not at all.");
        }

        if (stopped)
        {
            lines.Add(
                "The pass stopped before the end of its own list, so anything after the point it "
                + "stopped was not read by the AI at all.");
        }

        if (plan.Vendored.Count > 0)
        {
            lines.Add(Vendored(plan));
        }

        return lines;
    }

    /// <summary>
    /// What triage looked for, and what being passed over by it does not mean.
    /// </summary>
    /// <remarks>
    /// This replaced a sentence saying the files left out "were checked in full like the rest;
    /// there was nothing arriving from outside them for the AI to follow". Triage cannot know
    /// that. It looks for findings and for the names of calls, and a file that receives outside
    /// data through a function defined in another file names none of them. What it can say is
    /// what it looked for.
    /// </remarks>
    private static string Selection(int fileCount, TriageResult triage)
    {
        var text = "That reading is slower, so it is kept for files a check flagged, files that "
                   + "call into one of those, and files that use one of a list of calls that bring "
                   + "in data from outside the application, such as downloading something, "
                   + "opening a file or reading what was typed.";

        if (triage.TestFiles > 0)
        {
            text += " Test and example files are only included when a check flagged them.";
        }

        var passedOver = fileCount - triage.Qualified;

        if (passedOver <= 0)
        {
            return text;
        }

        return text
               + (passedOver == 1
                   ? " The other file was not picked. The selection goes by the names of calls in "
                     + "the code, so it cannot say whether outside data reaches that file."
                   : $" The other {passedOver:N0} were not picked. The selection goes by the names "
                     + "of calls in the code, so it cannot say whether outside data reaches them.");
    }

    /// <summary>
    /// Names the languages here that the selection's list of calls was not written for.
    /// </summary>
    /// <remarks>
    /// A Go service that takes every byte it handles off the network can match nothing on a list
    /// written in C# and JavaScript terms, and without this sentence the report would read as
    /// though it had nothing worth a second look.
    /// </remarks>
    private static string Unpatterned(IReadOnlyList<string> languages)
    {
        var named = languages.Count == 1
            ? languages[0]
            : $"{string.Join(", ", languages.Take(languages.Count - 1))} and {languages[^1]}";

        var which = languages.Count switch
        {
            1 => "a file in that language",
            2 => "a file in either of them",
            _ => "a file in any of them",
        };

        return "The list of calls the selection looks for is written for C#, JavaScript, "
               + $"TypeScript and Lua. This application also has code in {named}, so {which} can "
               + "take in data from outside without being picked.";
    }

    /// <summary>
    /// Names the bundled third-party code the review skipped.
    /// </summary>
    /// <remarks>
    /// Skipping it is a choice worth making: it is somebody else's library, inlined by a build
    /// tool, and paying a frontier model to read a copy of a published package is money spent on
    /// the wrong question. It is only defensible while the report says which packages went
    /// unread, because they are still inside the application and nothing else here mentions them.
    /// </remarks>
    private static string Vendored(DeepPassPlan plan)
    {
        var names = plan.Vendored
            .Select(v => v.Name)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        var shown = string.Join(", ", names.Take(10));
        var rest = names.Count > 10 ? $", and {names.Count - 10:N0} more" : "";
        var lines = plan.Vendored.Sum(v => v.LastLine - v.FirstLine + 1);

        return $"{names.Count:N0} third-party librar{(names.Count == 1 ? "y" : "ies")} compiled "
               + $"into this application's own files were left out of the AI review "
               + $"({lines:N0} lines): {shown}{rest}. They are somebody else's code, and no "
               + "version ships with them, so they could not be checked for advisories either.";
    }

    /// <summary>
    /// A share, never rounded up to the whole.
    /// </summary>
    /// <remarks>
    /// 99.6% of an application is not all of it, and printing 100 there is the one rounding this
    /// report cannot afford: it would say the AI read everything when it had not.
    /// </remarks>
    private static int Percent(long part, long whole)
    {
        if (whole <= 0)
        {
            return 0;
        }

        // A chunk counts the newline at the end of each line it carries, so a file read in full
        // measures a handful of characters longer than the file. Clamped rather than corrected:
        // the difference is one character per line and the alternative is arithmetic nobody can
        // follow, but a share above 100 would be visibly nonsense.
        part = Math.Min(part, whole);

        var rounded = (int)Math.Round(part / (double)whole * 100);

        return part < whole ? Math.Min(rounded, 99) : Math.Min(rounded, 100);
    }

    /// <summary>
    /// The path as it appears in the progress line, shortened from the left when it is too
    /// long to show whole.
    /// </summary>
    /// <remarks>
    /// The line it goes in is one label of fixed width on screen. A deep path left uncut
    /// overran it in both directions, so the reader lost the file name off one end and the
    /// count off the other and was left watching a middle section of a path. Cutting from the
    /// left keeps the two identifying parts, the file name and the folder it sits in, and the
    /// full path of every file that was read is in the report either way.
    /// </remarks>
    private static string ForProgress(string relativePath)
    {
        const int max = 46;

        if (relativePath.Length <= max)
        {
            return relativePath;
        }

        // Cut on a folder boundary where there is one within reach: half a folder name reads
        // as the name of a different folder, whereas a dropped one is visibly dropped.
        var boundary = relativePath.IndexOf('/', relativePath.Length - max + 1);

        return boundary >= 0
            ? "…/" + relativePath[(boundary + 1)..]
            : "…" + relativePath[^(max - 1)..];
    }

    /// <summary>
    /// Decides what answers the deep pass, or why nothing can.
    /// </summary>
    /// <remarks>
    /// The local CLI route is gated to the developer audience here rather than in the UI, where
    /// a change to a view could lose it. Claude Code can act on the machine and the API cannot,
    /// so feeding it untrusted source is only defensible when the reader wrote that source.
    /// Every refusal returns a reason rather than falling back to the API, since somebody who
    /// asked for their subscription should not find their card was charged instead.
    /// </remarks>
    private static async Task<BackendChoice> ChooseAsync(
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        // An endpoint the reader nominated wins over everything else, because nominating one is
        // a more specific instruction than holding a key. Checked before the CLI so that
        // somebody who configured a local model is not quietly answered by a subscription.
        if (options.DeepPassEndpoint is { } endpoint)
        {
            if (OpenAiCompatibleBackend.RejectEndpoint(endpoint) is { } problem)
            {
                return new BackendChoice(null, $"The deep pass did not run. {problem}");
            }

            if (string.IsNullOrWhiteSpace(options.DeepPassModel))
            {
                return new BackendChoice(
                    null,
                    "The deep pass did not run: an endpoint was configured but no model was "
                    + "named, and a chat-completions request has to say which model to use.");
            }

            return new BackendChoice(
                new OpenAiCompatibleBackend(
                    endpoint, options.DeepPassEndpointKey, options.DeepPassModel),
                null);
        }

        if (!options.DeepPassUseLocalCli)
        {
            return new BackendChoice(
                new DeepPassClient(options.DeepPassApiKey!, options.DeepPassModel), null);
        }

        if (options.Audience != Audience.Developer)
        {
            return new BackendChoice(
                null,
                "The deep pass did not run. Answering it through Claude Code on this machine is "
                + "offered only when reviewing an application you built yourself, because it "
                + "means handing code to a tool that can act on this computer. Scans of "
                + "software from elsewhere use the Anthropic API instead, which cannot.");
        }

        if (ClaudeCodeCliLocator.Locate() is not { } cli)
        {
            return new BackendChoice(
                null,
                "The deep pass did not run: no Claude Code installation was found on this "
                + "machine. Install it, or supply an Anthropic API key instead.");
        }

        var auth = await ClaudeCodeCliBackend.CheckAuthenticationAsync(cli, cancellationToken)
            .ConfigureAwait(false);

        return auth.SignedIn
            ? new BackendChoice(new ClaudeCodeCliBackend(cli, options.DeepPassModel), null)
            : new BackendChoice(null, auth.Problem);
    }
}
