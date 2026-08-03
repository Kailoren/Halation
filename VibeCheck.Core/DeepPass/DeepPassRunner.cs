using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.DeepPass;

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
            return new DeepPassResult { Limitations = [chosen.Problem!] };
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
            return new DeepPassResult
            {
                Backend = client.Description,
                Billed = client.BillsTheReader,
                Limitations =
                [
                    "The deep pass ran but found nothing worth reading: no file in this "
                    + "application handles input it does not control.",
                ],
            };
        }

        var findings = new List<Finding>();
        var limitations = new List<string>();
        var usage = new TokenUsage();
        var examined = 0;
        var fellBack = 0;
        var discarded = 0;

        foreach (var file in triaged)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Counter first, path last. The count is the part that says how much is left and
            // it is the same length every time; the path is the part that varies without
            // bound, so anything the label cannot fit comes off the end of the path rather
            // than off the progress.
            progress?.Report(new ScanProgress(
                ScanStage.Analysing,
                $"Deep pass {examined + 1} of {triaged.Count}: {ForProgress(file.File.RelativePath)}",
                (int)((examined + 1) / (double)triaged.Count * 100)));

            var review = await client.ReviewAsync(file, cancellationToken).ConfigureAwait(false);

            findings.AddRange(review.Findings);
            usage += review.Usage;
            discarded += review.LowConfidenceDiscarded;
            examined++;

            if (review.ServedByFallback)
            {
                fellBack++;
            }

            if (review.Limitation is not null)
            {
                limitations.Add(review.Limitation);
            }
        }

        // Which thing answered. Two backends run different models under different settings, so
        // a reader comparing two reports of the same application is owed this before they start
        // wondering why the findings differ.
        limitations.Add($"The deep pass was answered by {client.Description}.");

        // Said whether or not anything was found, and said in a way that distinguishes a
        // complete pass from a truncated one. The old wording covered both cases in one
        // sentence and read as a shortfall in both, which understated a scan that had in fact
        // read everything worth reading. It also implied the remaining files went unexamined,
        // which was untrue: every recovered file goes through the rule pass, and this is a
        // second read of the subset that handles untrusted input.
        limitations.Add(
            triage.HitCeiling
                ? $"The deep pass read {examined} files, but {triage.Qualified:N0} of the "
                  + $"{files.Count:N0} recovered files qualified for it. The ceiling on how many "
                  + "are sent stopped it early, so "
                  + $"{triage.Qualified - triaged.Count:N0} files that handle untrusted input "
                  + "were not read by it. Raise the limit to cover them."
                : $"The deep pass read {examined} of {files.Count:N0} recovered files: every "
                  + "file that handles input the application does not control, or that calls "
                  + "into code a rule flagged. The rest were not skipped, they were read by the "
                  + "rule pass like everything else and had no untrusted input for the deep "
                  + "pass to reason about.");

        // Stated once, here, rather than repeated on every finding. A hedge attached to each
        // item stops being read and starts reading as a tool that does not trust its own
        // output.
        limitations.Add(
            "Deep pass findings are inferred by a language model rather than matched by a "
            + "rule. Each one quotes the code it is based on so it can be checked, and none of "
            + "them can trigger a do-not-install verdict.");

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
                $"{fellBack} of the {examined} files read were declined by the requested model "
                + "on policy grounds and reviewed by a substitute model instead. Those reviews "
                + "are not directly comparable with the rest.");
        }

        return new DeepPassResult
        {
            Findings = findings,
            Limitations = limitations,
            FilesExamined = examined,
            Usage = usage,
            Backend = client.Description,
            Billed = client.BillsTheReader,
        };
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
    /// <para>
    /// The local CLI route is gated to the developer audience, and that gate lives here rather
    /// than in the UI. Claude Code is an agent with shell and filesystem access; the API is an
    /// endpoint that cannot execute anything. Feeding source recovered from untrusted software
    /// into the former is only defensible when the reader wrote that software. The flags this
    /// backend passes reduce the risk, but they are a third party's flags and a weaker boundary
    /// than an endpoint that has no hands. A gate enforced in the core cannot be lost to a
    /// change in a view.
    /// </para>
    /// <para>
    /// Every refusal below returns a reason rather than silently falling back to the API. A
    /// reader who asked for their subscription to be used should not discover afterwards that
    /// their card was charged instead.
    /// </para>
    /// </remarks>
    private static async Task<BackendChoice> ChooseAsync(
        ScanOptions options,
        CancellationToken cancellationToken)
    {
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
