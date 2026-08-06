using System.Net.Http.Json;
using System.Text.Json;

namespace VibeCheck.Core.DeepPass;

/// <summary>One model a local runtime already has, and how big it is on disk.</summary>
/// <param name="Id">The tag exactly as the runtime names it, which is what a request must say.</param>
/// <param name="Bytes">
/// Size on disk, or zero when the runtime did not say. The file size is the best available
/// proxy for what the model will want in video memory, so a zero here is the difference between
/// advising somebody and guessing at them.
/// </param>
public sealed record LocalModel(string Id, long Bytes);

/// <summary>A model runtime answering on this machine.</summary>
/// <param name="Name">Which one, for saying so on screen.</param>
/// <param name="Endpoint">Its chat-completions URL, ready to be stored as it is.</param>
/// <param name="Models">What it has, which may legitimately be empty.</param>
public sealed record LocalRuntime(string Name, Uri Endpoint, IReadOnlyList<LocalModel> Models);

/// <summary>
/// Looks for a model runtime already running on this machine.
/// </summary>
/// <remarks>
/// <para>
/// The local route is the only one where the reader's source never leaves the machine, and until
/// now reaching it meant knowing a port number and a model tag from memory. Asking the two
/// runtimes that exist is both faster and more accurate than asking the reader, because what a
/// server reports is what it will actually accept: a tag typed from memory that is off by a
/// suffix comes back as a 404 halfway through a scan.
/// </para>
/// <para>
/// <b>Loopback only, and fixed ports.</b> Nothing here takes a hostname from anywhere, so this
/// cannot be pointed at a network by configuration, by a stored file, or by anything read out of
/// the application being scanned.
/// </para>
/// </remarks>
public static class LocalRuntimeProbe
{
    /// <summary>The two runtimes, named once so nothing has to spell them again.</summary>
    /// <remarks>
    /// Constants rather than literals because these names are matched on, not only displayed:
    /// which runtime is answering decides which command a reader is given, and a comparison
    /// against a hand-typed string is a defect waiting for a rename.
    /// </remarks>
    public const string OllamaName = "Ollama";

    /// <inheritdoc cref="OllamaName"/>
    public const string LmStudioName = "LM Studio";

    /// <summary>Whether this runtime is LM Studio, which spells and fetches models differently.</summary>
    public static bool IsLmStudio(string? runtimeName) =>
        string.Equals(runtimeName, LmStudioName, StringComparison.OrdinalIgnoreCase);

    /// <summary>Where the two runtimes listen, and whether Ollama's extra endpoint is worth asking.</summary>
    private sealed record Candidate(string Name, int Port, bool Ollama);

    private static readonly Candidate[] Candidates =
    [
        new(OllamaName, 11434, Ollama: true),
        new(LmStudioName, 1234, Ollama: false),
    ];

    /// <summary>
    /// Short on purpose. This runs while somebody is looking at a dialog, and a machine with
    /// nothing listening refuses the connection immediately, so the only thing this timeout
    /// governs is how long a wedged server can hold up the interface.
    /// </summary>
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(3);

    /// <summary>Asks both runtimes at once and returns whichever answered.</summary>
    public static async Task<IReadOnlyList<LocalRuntime>> FindAsync(
        HttpMessageHandler? handler = null,
        CancellationToken cancellationToken = default)
    {
        using var http = handler is null
            ? new HttpClient { Timeout = Patience }
            : new HttpClient(handler, disposeHandler: false) { Timeout = Patience };

        var found = await Task.WhenAll(
                Candidates.Select(c => AskAsync(http, c, cancellationToken)))
            .ConfigureAwait(false);

        return [.. found.OfType<LocalRuntime>()];
    }

    private static async Task<LocalRuntime?> AskAsync(
        HttpClient http,
        Candidate candidate,
        CancellationToken cancellationToken)
    {
        var root = $"http://localhost:{candidate.Port}";

        // Ollama's own listing carries sizes and the compatible one does not, so it is asked
        // first where it exists. Both name models identically, so either answer is usable.
        var models = candidate.Ollama
            ? await TagsAsync(http, root, cancellationToken).ConfigureAwait(false)
              ?? await ModelsAsync(http, root, cancellationToken).ConfigureAwait(false)
            : await ModelsAsync(http, root, cancellationToken).ConfigureAwait(false);

        return models is null
            ? null
            : new LocalRuntime(
                candidate.Name,
                new Uri($"{root}/v1/chat/completions"),
                models);
    }

    /// <summary>
    /// The OpenAI-compatible listing, which every server of this shape serves.
    /// </summary>
    /// <remarks>
    /// Returns an empty list rather than null when the server answers with no models. A runtime
    /// that is running and empty needs different advice from one that is not running at all, and
    /// collapsing the two would send somebody off to install what they already have.
    /// </remarks>
    private static async Task<IReadOnlyList<LocalModel>?> ModelsAsync(
        HttpClient http,
        string root,
        CancellationToken cancellationToken)
    {
        var document = await ReadAsync(http, $"{root}/v1/models", cancellationToken)
            .ConfigureAwait(false);

        if (document is null)
        {
            return null;
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("data", out var data)
                || data.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            return
            [
                .. data.EnumerateArray()
                    .Select(m => m.TryGetProperty("id", out var id) ? id.GetString() : null)
                    .Where(id => !string.IsNullOrWhiteSpace(id))
                    .Select(id => new LocalModel(id!, 0)),
            ];
        }
    }

    /// <summary>Ollama's native listing, which is the only one that reports sizes.</summary>
    private static async Task<IReadOnlyList<LocalModel>?> TagsAsync(
        HttpClient http,
        string root,
        CancellationToken cancellationToken)
    {
        var document = await ReadAsync(http, $"{root}/api/tags", cancellationToken)
            .ConfigureAwait(false);

        if (document is null)
        {
            return null;
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("models", out var models)
                || models.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var found = new List<LocalModel>();

            foreach (var model in models.EnumerateArray())
            {
                if (!model.TryGetProperty("name", out var name)
                    || name.GetString() is not { Length: > 0 } tag)
                {
                    continue;
                }

                var bytes = model.TryGetProperty("size", out var size)
                            && size.TryGetInt64(out var value)
                    ? value
                    : 0;

                found.Add(new LocalModel(tag, bytes));
            }

            return found;
        }
    }

    /// <summary>
    /// One GET. Null for every failure, because every failure means the same thing here: there
    /// is nothing usable at this address, and the reader is told that rather than shown a
    /// networking error they did not ask for.
    /// </summary>
    private static async Task<JsonDocument?> ReadAsync(
        HttpClient http,
        string url,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(url, cancellationToken).ConfigureAwait(false);

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<JsonDocument>(cancellationToken)
                    .ConfigureAwait(false)
                : null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (TaskCanceledException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
