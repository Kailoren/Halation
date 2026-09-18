using Halation.Core.Recovery;

namespace Halation.Core.DeepPass;

/// <summary>One file as the plan will send it.</summary>
/// <param name="Triaged">The triaged file.</param>
/// <param name="Requests">The requests that will be sent for it, in order.</param>
/// <param name="Total">How many it would take to cover the file, before any ceiling.</param>
/// <param name="Vendored">Bundled third-party regions left out of the review.</param>
public sealed record PlannedFile(
    TriagedFile Triaged,
    IReadOnlyList<DeepPassChunk> Requests,
    int Total,
    IReadOnlyList<VendoredRegion> Vendored)
{
    /// <summary>Whether every part of this file's own code will be sent.</summary>
    public bool Whole => Requests.Count == Total;
}

/// <summary>
/// Exactly what a deep pass will send, worked out before it sends any of it.
/// </summary>
/// <remarks>
/// <para>
/// One object, used by the run and by anything that wants to say beforehand what the run will
/// cost. They were separate arithmetic until a measured scan showed the estimate describing five
/// requests where the pass would have made five truncated ones, so the estimate and the pass are
/// now the same calculation and cannot drift.
/// </para>
/// <para>
/// The ceiling is on requests rather than on files, because a file is no longer one request.
/// Forty files used to bound the spend; with a 1.4 million character bundle among them it does
/// not bound anything, and the reader would learn the real figure from their invoice.
/// </para>
/// </remarks>
public sealed record DeepPassPlan
{
    /// <summary>Every request, in the order they will be sent.</summary>
    public IReadOnlyList<DeepPassChunk> Requests { get; init; } = [];

    public IReadOnlyList<PlannedFile> Files { get; init; } = [];

    /// <summary>Characters of application code recovered, which is what coverage is measured against.</summary>
    public long CodeChars { get; init; }

    /// <summary>Characters of that code the requests carry.</summary>
    public long CharsToSend => Requests.Sum(r => (long)r.Chars);

    /// <summary>Bundled third-party regions left out of the review, across every file.</summary>
    public IReadOnlyList<VendoredRegion> Vendored =>
        [.. Files.SelectMany(f => f.Vendored)];

    /// <summary>True when the request ceiling, rather than the code, decided where to stop.</summary>
    public bool HitRequestCeiling { get; init; }

    /// <summary>Files that will be read in part only, because the ceiling cut them short.</summary>
    public int PartialFiles => Files.Count(f => !f.Whole && f.Requests.Count > 0);

    /// <summary>Files that qualified and will not be read at all.</summary>
    public int UnreadFiles => Files.Count(f => f.Requests.Count == 0);

    /// <summary>
    /// Works out what will be sent.
    /// </summary>
    /// <param name="recovered">Every file the scan recovered, which is the coverage denominator.</param>
    /// <param name="triaged">The files triage selected, most relevant first.</param>
    /// <param name="maxRequests">Ceiling on requests for the whole pass.</param>
    /// <remarks>
    /// Files are filled in triage order and each is filled whole before the next is started, so
    /// a budget that runs out runs out on the least likely candidates. A file that gets no
    /// request at all is still listed, because "not read" is a fact the report states rather
    /// than an absence it leaves the reader to notice.
    /// </remarks>
    public static DeepPassPlan Build(
        IReadOnlyList<RecoveredFile> recovered,
        IReadOnlyList<TriagedFile> triaged,
        int maxRequests)
    {
        ArgumentNullException.ThrowIfNull(recovered);
        ArgumentNullException.ThrowIfNull(triaged);

        var files = new List<PlannedFile>(triaged.Count);
        var requests = new List<DeepPassChunk>();
        var budget = Math.Max(1, maxRequests);
        var cut = false;

        foreach (var file in triaged)
        {
            var split = DeepPassChunker.Split(file);
            var room = Math.Max(0, budget - requests.Count);
            var taken = split.Chunks.Take(room).ToList();

            cut |= taken.Count < split.Chunks.Count;
            requests.AddRange(taken);

            files.Add(new PlannedFile(file, taken, split.Chunks.Count, split.Vendored));
        }

        return new DeepPassPlan
        {
            Requests = requests,
            Files = files,
            CodeChars = recovered.Sum(f => (long)f.Content.Length),
            HitRequestCeiling = cut,
        };
    }
}
