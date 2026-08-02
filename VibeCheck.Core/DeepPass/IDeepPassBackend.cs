namespace VibeCheck.Core.DeepPass;

/// <summary>
/// Something that can review one file and report what it found.
/// </summary>
/// <remarks>
/// <para>
/// There is more than one way to reach a model. The Anthropic API is one, billed to a key the
/// reader bought. A Claude Code installation the reader already has is another, billed to a
/// subscription they are already paying for. The pass itself should not care which answered,
/// so the difference is confined to an implementation of this.
/// </para>
/// <para>
/// What must not vary is the question. Both implementations ask through
/// <see cref="DeepPassPrompt"/> and read the answer back through it, so two scans differ
/// because the application differed and not because the plumbing did.
/// </para>
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
    /// Reviews one file. Returns a result carrying a limitation rather than throwing, so a
    /// single failure costs one file's coverage instead of the whole pass.
    /// </summary>
    Task<FileReview> ReviewAsync(TriagedFile triaged, CancellationToken cancellationToken = default);
}
