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
        var triaged = DeepPassTriage.Select(files, deterministicFindings, options.DeepPassMaxFiles);

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

        foreach (var file in triaged)
        {
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report(new ScanProgress(
                ScanStage.Analysing,
                $"Deep pass: reading {file.File.RelativePath} ({examined + 1} of {triaged.Count})",
                (int)((examined + 1) / (double)triaged.Count * 100)));

            var review = await client.ReviewAsync(file, cancellationToken).ConfigureAwait(false);

            findings.AddRange(review.Findings);
            usage += review.Usage;
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

        // Said whether or not anything was found. A deep pass that read 12 of an
        // application's files has not cleared the other 300, and the report has to say which
        // it did rather than leaving the reader to assume.
        limitations.Add(
            $"The deep pass read {examined} of {files.Count:N0} recovered files, chosen for "
            + "handling untrusted input or for calling code a rule flagged. Files it did not "
            + "read were not examined by it.");

        limitations.Add(
            "Deep pass findings are inferred by a language model rather than matched by a "
            + "rule. They can be wrong, and none of them can trigger a do-not-install verdict.");

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
