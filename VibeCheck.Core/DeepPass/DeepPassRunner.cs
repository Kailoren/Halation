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
    public static async Task<DeepPassResult> RunAsync(
        IReadOnlyList<RecoveredFile> files,
        IReadOnlyList<Finding> deterministicFindings,
        ScanOptions options,
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

        var triaged = DeepPassTriage.Select(files, deterministicFindings, options.DeepPassMaxFiles);

        if (triaged.Count == 0)
        {
            return new DeepPassResult
            {
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

        using var client = new DeepPassClient(options.DeepPassApiKey!, options.DeepPassModel);

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
        };
    }
}
