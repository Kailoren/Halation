namespace VibeCheck.Core.DeepPass;

/// <summary>Whether a model will fit in the video memory it has been offered.</summary>
public enum ModelFit
{
    /// <summary>Not enough is known about the model or the machine to say.</summary>
    Unknown,

    /// <summary>Fits with room for the context on top.</summary>
    Comfortable,

    /// <summary>Fits, but with nothing spare. Expect it to be slower under load.</summary>
    Tight,

    /// <summary>Does not fit. It will run, partly on the processor, and it will be slow.</summary>
    Spills,
}

/// <summary>One model worth suggesting, and the machine it suits.</summary>
/// <param name="Tag">The tag to pull and to name in a request.</param>
/// <param name="Label">How it is described in a sentence.</param>
/// <param name="WantsVideoBytes">Video memory below which this is the wrong choice.</param>
/// <param name="DownloadBytes">Roughly what pulling it costs in disk and bandwidth.</param>
/// <param name="Note">What the reader gains or gives up at this size.</param>
public sealed record LocalModelChoice(
    string Tag,
    string Label,
    long WantsVideoBytes,
    long DownloadBytes,
    string Note)
{
    /// <summary>The command that fetches it, which is the only step this application cannot do.</summary>
    public string PullCommand => $"ollama pull {Tag}";
}

/// <summary>
/// Which local model suits which graphics card, and whether one already installed will fit.
/// </summary>
/// <remarks>
/// <para>
/// Every reader has different hardware, and the difference between a local deep pass that takes
/// twenty minutes and one that takes three hours is entirely whether the model fitted in video
/// memory. That is not something somebody should have to find out by running a scan overnight.
/// </para>
/// <para>
/// <b>The rule is published rather than only the table.</b> A model's file size is roughly what
/// it occupies in video memory, plus something for the context, so a reader who prefers a
/// different model can size it themselves rather than being limited to these four. The
/// suggestions are a starting point and the arithmetic is the actual answer: the catalogue of
/// models moves faster than this application ships, and a table presented as authoritative would
/// go quietly out of date.
/// </para>
/// <para>
/// One family across all four sizes on purpose. Comparing scans is hard enough without the
/// smallest and largest suggestions being different models that disagree for reasons of their
/// own, and a reader who moves up a size should get more of the same judgment rather than a
/// different one.
/// </para>
/// </remarks>
public static class LocalModelGuide
{
    private const long GB = 1024L * 1024 * 1024;

    /// <summary>
    /// What the context costs on top of the weights.
    /// </summary>
    /// <remarks>
    /// The deep pass sends whole files, up to sixty thousand characters each, so the context is
    /// not a rounding error here the way it is for chat. A gigabyte and a half is the headroom
    /// that separates a model which fits from one that fits until it is asked to read something.
    /// </remarks>
    private const long ContextHeadroom = 3 * GB / 2;

    /// <summary>The suggestions, smallest first.</summary>
    public static IReadOnlyList<LocalModelChoice> Choices { get; } =
    [
        new(
            "qwen2.5-coder:3b",
            "3B",
            WantsVideoBytes: 4 * GB,
            DownloadBytes: 19 * GB / 10,
            "For a card with little memory to spare. It will find noticeably less than the "
            + "larger sizes and will miss reasoning that spans several files."),

        new(
            "qwen2.5-coder:7b",
            "7B",
            WantsVideoBytes: 13 * GB / 2,
            DownloadBytes: 47 * GB / 10,
            "The usual choice for an 8GB card. Enough to reason about a file properly without "
            + "spilling onto the processor."),

        new(
            "qwen2.5-coder:14b",
            "14B",
            WantsVideoBytes: 11 * GB,
            DownloadBytes: 9 * GB,
            "Better at reachability and at guards that are incomplete rather than absent. "
            + "Wants a 12GB card or more."),

        new(
            "qwen2.5-coder:32b",
            "32B",
            WantsVideoBytes: 22 * GB,
            DownloadBytes: 20 * GB,
            "The closest a model on your own machine gets to the hosted route. Wants 24GB."),
    ];

    /// <summary>
    /// The largest suggestion that fits the card, or null when none of them do.
    /// </summary>
    /// <remarks>
    /// Null rather than the smallest, because "the smallest will technically start" is not a
    /// recommendation and presenting it as one would set somebody up for a scan that runs on the
    /// processor all night. The caller says so in words instead.
    /// </remarks>
    public static LocalModelChoice? Recommend(long videoBytes) =>
        videoBytes <= 0
            ? null
            : Choices.Where(c => c.WantsVideoBytes <= videoBytes)
                .OrderByDescending(c => c.WantsVideoBytes)
                .FirstOrDefault();

    /// <summary>Whether a model of this size will fit in this much video memory.</summary>
    public static ModelFit Judge(long modelBytes, long videoBytes) =>
        modelBytes <= 0 || videoBytes <= 0 ? ModelFit.Unknown
        : modelBytes + ContextHeadroom <= videoBytes ? ModelFit.Comfortable
        : modelBytes <= videoBytes ? ModelFit.Tight
        : ModelFit.Spills;

    /// <summary>
    /// Whether a tag names a model trained on code rather than a general assistant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Crude by necessity, since the only thing a runtime reports about an installed model is
    /// its name. It earns its place anyway: a reader who pulled a general chat model for
    /// something else and a code model for this will have both installed, both will fit the same
    /// card, and sorting them by size alone puts whichever happens to be larger at the top. That
    /// is the row somebody clicks.
    /// </para>
    /// <para>
    /// Wrong in the harmless direction. A code model missed by this list is merely sorted lower,
    /// and the reader can still pick it; nothing is hidden and nothing is refused.
    /// </para>
    /// </remarks>
    public static bool LooksCodeCapable(string? tag) =>
        tag is not null
        && CodeMarkers.Any(marker => tag.Contains(marker, StringComparison.OrdinalIgnoreCase));

    /// <summary>"code" covers codellama, codegemma, codestral and starcoder between them.</summary>
    private static readonly string[] CodeMarkers = ["code", "coder", "devstral"];

    /// <summary>
    /// That verdict as the phrase shown beside the model.
    /// </summary>
    /// <remarks>
    /// Short, because it sits on a row that already carries a name and a size, and because the
    /// reason behind it is given once in <see cref="Advise"/> rather than repeated on every
    /// line. The first version explained the mechanism on each row and ran off the edge of the
    /// button.
    /// </remarks>
    public static string Describe(ModelFit fit) => fit switch
    {
        ModelFit.Comfortable => "fits your card",
        ModelFit.Tight => "only just fits",
        ModelFit.Spills => "too big, it will run on the processor and be slow",
        _ => "size unknown",
    };

    /// <summary>
    /// What this machine can run, in a sentence, including when the answer is "not much".
    /// </summary>
    public static string Advise(long videoBytes)
    {
        if (videoBytes <= 0)
        {
            return "Set your card's memory above and this will say which model to use. As a "
                   + "rule, a model needs about its own file size in video memory, plus a "
                   + "gigabyte or two for the file being read.";
        }

        var gb = videoBytes / (double)GB;

        if (Recommend(videoBytes) is not { } choice)
        {
            return $"With {gb:0.#}GB of video memory, none of the suggestions below will fit "
                   + "properly. The smallest will still run, mostly on your processor, which "
                   + "works but can take hours rather than minutes on a large application. One "
                   + "of the other two routes will serve you better.";
        }

        return $"With {gb:0.#}GB of video memory, {choice.Tag} is the largest that fits. A model "
               + "needs roughly its own file size in video memory plus a gigabyte or two for the "
               + "file it is reading, so anything larger runs partly on your processor and slows "
               + "down sharply.";
    }

    /// <summary>
    /// Bytes as the reader would say them, for sizes that are always gigabytes here.
    /// </summary>
    /// <remarks>
    /// Binary gigabytes, the same unit the card's memory is reported in, so the two numbers on
    /// screen can be compared against each other. That is the comparison this whole file exists
    /// to support. It does mean a model reads slightly smaller here than in <c>ollama list</c>,
    /// which counts in decimal gigabytes: 4.4 against 4.7 for the same file. Matching Ollama
    /// instead would make every model look closer to fitting than it is, which is the one error
    /// worth avoiding.
    /// </remarks>
    public static string Gigabytes(long bytes) =>
        bytes <= 0 ? "size unknown" : $"{bytes / (double)GB:0.#}GB";
}
