namespace Halation.Core.DeepPass;

/// <summary>
/// Something that can review one file and report what it found.
/// </summary>
/// <remarks>
/// Two ways to reach a model, one billed to a key the reader bought and one to a subscription
/// they already hold, and the pass should not care which answered. What must not vary is the
/// question: both ask through <see cref="DeepPassPrompt"/>, so two scans differ because the
/// application differed and not because the plumbing did.
/// </remarks>
public interface IDeepPassBackend : IDisposable
{
    /// <summary>
    /// How this backend describes itself in the report, e.g. "the Anthropic API".
    /// </summary>
    /// <remarks>
    /// Stated rather than assumed. Two backends run different models under different settings,
    /// so a reader comparing two reports is owed the fact that a different thing answered.
    /// </remarks>
    string Description { get; }

    /// <summary>
    /// Whether the tokens this backend reports correspond to money charged to the reader.
    /// </summary>
    /// <remarks>
    /// True for a backend spending an API key the reader bought, false for one spending a
    /// subscription they already hold. The distinction is not cosmetic: both routes can price
    /// a run in dollars, but only one of them results in a charge, and telling somebody a scan
    /// cost them money when their card was never touched is a false statement in a report whose
    /// whole value is that it does not make them.
    /// </remarks>
    bool BillsTheReader { get; }

    /// <summary>
    /// What this many tokens are worth in US dollars, or null when the backend cannot know.
    /// </summary>
    /// <remarks>
    /// Asked of the backend rather than computed from a table here, because only the backend
    /// knows what it is talking to. A configurable endpoint might be a frontier model at
    /// fifteen dollars a million tokens or a model on the reader's own machine at nothing, and
    /// the difference is not inferable from the request. Null means the honest report says how
    /// many tokens were spent and declines to say what they cost, which is a better answer than
    /// a confident number arrived at by pricing someone else's model at Anthropic's rates.
    /// </remarks>
    decimal? PriceOf(TokenUsage usage);

    /// <summary>
    /// Reviews one file. Returns a result carrying a limitation rather than throwing, so a
    /// single failure costs one file's coverage instead of the whole pass.
    /// </summary>
    Task<FileReview> ReviewAsync(TriagedFile triaged, CancellationToken cancellationToken = default);
}
