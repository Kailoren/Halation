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
    /// <remarks>
    /// <para>
    /// <b>The download sizes are the registry manifests' own byte totals, not round gigabytes.</b>
    /// They were previously written as the figures <c>ollama list</c> prints, which are decimal
    /// gigabytes, into a field <see cref="Gigabytes"/> renders as binary ones. The same model then
    /// read 4.7GB as a suggestion and 4.4GB once installed, which is precisely the confusion that
    /// method exists to avoid. Taking the byte count means the number a reader is shown before
    /// pulling matches the one shown afterwards.
    /// </para>
    /// <para>
    /// <b>1.5B was removed on 2026-08-06 after being measured.</b> Pointed at one real
    /// application's source it read all eighteen qualifying files, answered every request in
    /// under a second and a half, and returned <i>nothing at all</i>: no findings, no error and
    /// no limitation. That is the worst failure this tool has, because a scan by a model that
    /// cannot do the job is indistinguishable from a scan that found nothing to report. 7B over
    /// the same code returned twenty-two points to look at. Suggesting a size that produces a
    /// silent all-clear is worse than suggesting none, so the smallest suggestion now wants a
    /// 6.5GB card and <see cref="Recommend"/> returns null below that, which the caller states
    /// in words. 3B is not a replacement: it is the one size in this family published under
    /// Qwen's research licence rather than Apache 2.0, and leading somebody scanning their
    /// commercial application towards it is an avoidable trap.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<LocalModelChoice> Choices { get; } =
    [
        new(
            "qwen2.5-coder:7b",
            "7B",
            WantsVideoBytes: 13 * GB / 2,
            DownloadBytes: 4_683_087_074,
            "The usual choice for an 8GB card. Enough to reason about a file properly without "
            + "spilling onto the processor."),

        new(
            "qwen2.5-coder:14b",
            "14B",
            WantsVideoBytes: 11 * GB,
            DownloadBytes: 8_988_123_810,
            "Better at reachability and at guards that are incomplete rather than absent. "
            + "Wants a 12GB card or more."),

        new(
            "qwen2.5-coder:32b",
            "32B",
            WantsVideoBytes: 22 * GB,
            DownloadBytes: 19_851_349_410,
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
    /// Whether a tag names one of Ollama's cloud models, which are not on this machine at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is a privacy check, not a performance one.</b> Ollama serves its cloud models
    /// through the same <c>localhost:11434</c> as local ones: the daemon sees the <c>-cloud</c>
    /// suffix, attaches the reader's ollama.com credentials and forwards the request. A loopback
    /// address is therefore not proof that anything stays on the machine, and treating it as
    /// proof would have this application state that nothing was uploaded while it uploaded the
    /// reader's source code. That is the one kind of mistake this whole tool exists not to make.
    /// </para>
    /// <para>
    /// The suffix is the only signal available: cloud models appear in the runtime's own listing
    /// beside local ones, distinguished by the name and by reporting no size. A local model
    /// deliberately named to end in <c>-cloud</c> would be misread, and that is the safe
    /// direction to be wrong in, since it overstates what leaves the machine rather than
    /// understating it.
    /// </para>
    /// </remarks>
    public static bool IsCloudModel(string? tag) =>
        tag is not null && tag.TrimEnd().EndsWith("-cloud", StringComparison.OrdinalIgnoreCase);

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
    /// What this machine can run, in a sentence, including when there is no usable card.
    /// </summary>
    /// <remarks>
    /// <para>
    /// System memory is part of the answer rather than a footnote. A model with no graphics card
    /// to sit in runs on the processor out of ordinary memory, and that works: it is the reader's
    /// decision whether it is fast enough, not this application's. An earlier version of this
    /// sentence told anybody without a card to use one of the hosted routes instead, which
    /// substituted a judgment about speed for the reader's own reason for wanting local at all.
    /// </para>
    /// <para>
    /// <b>The advice inverts without a card.</b> With video memory the binding constraint is
    /// capacity, so the largest model that fits is the best one. On a processor the constraint is
    /// speed, and a machine with 64GB of memory can load a model far larger than it can run in
    /// any reasonable time, so the right suggestion is a small one.
    /// </para>
    /// </remarks>
    public static string Advise(long videoBytes, long systemBytes = 0)
    {
        if (videoBytes <= 0)
        {
            return OnTheProcessor(systemBytes);
        }

        var gb = videoBytes / (double)GB;

        if (Recommend(videoBytes) is not { } choice)
        {
            return $"With {gb:0.#}GB of video memory, none of the suggestions below fits "
                   + "entirely on the card. They will still run, with the rest on your "
                   + "processor, which works but is slow: expect hours rather than minutes on a "
                   + "large application. The smallest is the one to try.";
        }

        return $"With {gb:0.#}GB of video memory, {choice.Tag} is the largest that fits. A model "
               + "needs roughly its own file size in video memory plus a gigabyte or two for the "
               + "file it is reading, so anything larger runs partly on your processor and slows "
               + "down sharply.";
    }

    /// <summary>
    /// The no-card case, which is a real way to run this rather than a failure to run it.
    /// </summary>
    /// <remarks>
    /// The reason for the slowness is given because it is the one thing that decides whether a
    /// better processor would help. Speed here is set by memory bandwidth and by how fast the
    /// prompt can be read, not by core count, and the deep pass sends whole files, so it is
    /// heavier on the prompt than most things a model is asked to do. A reader told only "it
    /// will be slow" would reasonably go and buy more cores and find nothing changed.
    /// </remarks>
    private static string OnTheProcessor(long systemBytes)
    {
        // The smallest, and no fallback beneath it. There used to be one, and dropping 1.5B took
        // it away: what is left is the floor at which a local model returns anything useful at
        // all, so "or the smaller one if that proves too slow" now has nothing to point at.
        var smallest = Choices[0];

        // Worded as what happens rather than as a claim about what was detected. The box above
        // can be cleared on a machine that plainly does have a card, and "no graphics card was
        // found" then contradicts the adapter named two lines higher up.
        var opening = systemBytes > 0
            ? $"With no video memory to use, a model runs on your processor, out of the "
              + $"{systemBytes / (double)GB:0.#}GB of system memory. "
            : "With no video memory to use, a model runs on your processor, out of ordinary "
              + "system memory. ";

        return opening
               + "That works and nothing about it is second class, but it is slow, and slower "
               + "here than for chat: the deep pass sends whole files to be read, and reading a "
               + "long prompt is the part a processor is worst at. Speed depends on memory "
               + "bandwidth rather than core count, so more channels help and more cores mostly "
               + $"do not. Start with {smallest.Tag}, which is the smallest size worth running "
               + "for this, and expect a large application to take hours.";
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
