using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.DeepPass;

/// <summary>
/// Runs the deep pass over the triaged files and collects what it found.
/// </summary>
/// <remarks>
/// Files are reviewed one at a time rather than concatenated into a single request. A file
/// declined by the safety classifiers then costs that one file rather than the whole pass,
/// which matters here more than elsewhere: the request is asking about security weaknesses
/// in recovered code, and that is exactly the shape those classifiers watch for.
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
        long input = 0, output = 0;
        var examined = 0;

        using var client = new DeepPassClient(options.DeepPassApiKey!, options.DeepPassModel);

        foreach (var file in triaged)
        {
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report(new ScanProgress(
                ScanStage.Analysing,
                $"Deep pass: reading {file.File.RelativePath} ({examined + 1} of {triaged.Count})",
                (int)((examined + 1) / (double)triaged.Count * 100)));

            var (found, limitation, tokensIn, tokensOut) =
                await client.ReviewAsync(file, cancellationToken).ConfigureAwait(false);

            findings.AddRange(found);
            input += tokensIn;
            output += tokensOut;
            examined++;

            if (limitation is not null)
            {
                limitations.Add(limitation);
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

        return new DeepPassResult
        {
            Findings = findings,
            Limitations = limitations,
            FilesExamined = examined,
            InputTokens = input,
            OutputTokens = output,
        };
    }
}
