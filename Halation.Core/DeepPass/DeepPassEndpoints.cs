namespace Halation.Core.DeepPass;

/// <summary>
/// One provider a reader might point the deep pass at, and what it takes to reach it.
/// </summary>
/// <param name="Name">What the provider is called, as it appears on the button.</param>
/// <param name="Url">The exact chat-completions URL, path included.</param>
/// <param name="SuggestedModel">
/// A model to start from, or null where naming one would be a guess. Blank is the honest answer
/// for a provider whose catalogue turns over faster than this application ships: a wrong model
/// id comes back as a 400 that reads like a broken feature, whereas an empty box reads like a
/// question.
/// </param>
/// <param name="NeedsKey">Whether a key is required, which is false for anything local.</param>
/// <param name="Note">Where to find the model list, and whether anything leaves the machine.</param>
public sealed record DeepPassEndpointPreset(
    string Name,
    string Url,
    string? SuggestedModel,
    bool NeedsKey,
    string Note);

/// <summary>
/// The endpoints worth offering by name, and the tidying that turns what someone pastes into
/// the URL that will actually be requested.
/// </summary>
/// <remarks>
/// <para>
/// This exists because the one setting the deep pass cannot do without is also the one nobody
/// remembers. Ollama's port, Groq's <c>/openai</c> prefix and OpenRouter's <c>/api/v1</c> are
/// facts about somebody else's product, and getting one of them wrong produces a 404 that looks
/// like a fault in this application rather than a typo in a field.
/// </para>
/// <para>
/// In <see cref="Halation.Core"/> rather than in the interface because it is testable here and
/// not there, and because the path a request goes to is a property of the protocol rather than
/// of the window that collected it.
/// </para>
/// </remarks>
public static class DeepPassEndpoints
{
    /// <summary>The path every server of this shape serves chat completions from.</summary>
    private const string Completions = "/chat/completions";

    /// <summary>
    /// Presets, local first.
    /// </summary>
    /// <remarks>
    /// Ollama and LM Studio lead because they are the only two entries that answer the question
    /// an API key cannot: a deep pass that reads recovered source without any of it leaving the
    /// machine. The hosted providers follow in rough order of how likely a reader is to already
    /// hold a key for one.
    /// </remarks>
    public static IReadOnlyList<DeepPassEndpointPreset> Presets { get; } =
    [
        new(
            "Ollama",
            "http://localhost:11434/v1" + Completions,
            "qwen2.5-coder:14b",
            NeedsKey: false,
            "On this machine. Pull a model first, then name its tag here. Nothing is uploaded "
            + "and nothing is charged."),

        new(
            "LM Studio",
            "http://localhost:1234/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: false,
            "On this machine. Start its local server and copy the model id it lists. Nothing is "
            + "uploaded and nothing is charged."),

        new(
            "OpenAI",
            "https://api.openai.com/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Keys and the current model ids are at platform.openai.com."),

        new(
            "OpenRouter",
            // The path really is /api/v1 rather than /v1. Getting this wrong answers 404, and a
            // 404 from a provider you were told is supported reads as a broken feature.
            "https://openrouter.ai/api/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "One key for models from many providers. Model ids look like vendor/model."),

        new(
            "Google Gemini",
            "https://generativelanguage.googleapis.com/v1beta/openai" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Google's own OpenAI-compatible endpoint, not the Gemini API shape."),

        new(
            "Groq",
            "https://api.groq.com/openai/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Open-weight models, quickly. Model ids are at console.groq.com."),

        // Directly after Groq on purpose. The two are unrelated companies with near-identical
        // names, Groq having had it first, and a reader who picks the wrong one gets a 401 from a
        // provider they have no account with. Adjacent and distinctly labelled, the list answers
        // the question instead of setting the trap.
        new(
            "xAI (Grok)",
            "https://api.x.ai/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Grok, from xAI. Not the same company as Groq. Keys and current model ids are at "
            + "console.x.ai."),

        new(
            "Together",
            "https://api.together.xyz/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Open-weight models. Model ids look like vendor/model."),

        new(
            "DeepSeek",
            "https://api.deepseek.com/v1" + Completions,
            "deepseek-chat",
            NeedsKey: true,
            "Keys at platform.deepseek.com."),

        new(
            "Mistral",
            "https://api.mistral.ai/v1" + Completions,
            SuggestedModel: null,
            NeedsKey: true,
            "Keys and model ids are at console.mistral.ai."),
    ];

    /// <summary>
    /// Turns what a reader typed into the URL that will be requested, or null if it cannot be
    /// read as one at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every provider documents a base URL and none of them documents the same one, so a reader
    /// copying from a provider's page arrives with <c>https://api.openai.com/v1</c> while the
    /// request has to go to <c>.../v1/chat/completions</c>. Left alone that is a 404 on the first
    /// file of the scan, blamed on this application.
    /// </para>
    /// <para>
    /// <b>The caller is expected to show the result back.</b> Rewriting a field silently would
    /// make this a hidden transformation of the one setting that decides where source code is
    /// sent, and the whole argument for this tool is that it does not do things to you quietly.
    /// The dialog puts the normalised URL back in the box, so what is on screen is what will be
    /// requested.
    /// </para>
    /// <para>
    /// A missing scheme is filled in as https, except on loopback where http is both what was
    /// meant and the one case
    /// <see cref="OpenAiCompatibleBackend.RejectEndpoint"/> allows unencrypted. Guessing https
    /// for everything else is the safe direction to guess in: the worst outcome is a connection
    /// that fails rather than source code sent in the clear.
    /// </para>
    /// </remarks>
    public static Uri? Normalise(string? text)
    {
        var typed = text?.Trim();

        if (string.IsNullOrEmpty(typed))
        {
            return null;
        }

        // Without this, "localhost:11434/v1" parses as an absolute URI whose scheme is
        // "localhost", which is a valid parse and a useless one.
        if (!typed.Contains("://", StringComparison.Ordinal))
        {
            typed = (IsLocalName(typed) ? "http://" : "https://") + typed;
        }

        if (!Uri.TryCreate(typed, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.AbsolutePath.EndsWith(Completions, StringComparison.OrdinalIgnoreCase))
        {
            return uri;
        }

        // A bare host is the only case where the version segment is added as well. Nothing else
        // it could mean, and /v1 is what all but a couple of these servers use; the couple that
        // do not are in the presets above, so nobody has to know that from memory.
        var path = uri.AbsolutePath.TrimEnd('/');

        return new UriBuilder(uri)
        {
            Path = (path.Length == 0 ? "/v1" : path) + Completions,
        }.Uri;
    }

    /// <summary>
    /// Names an endpoint the way the interface and the report should: by where the code goes.
    /// </summary>
    /// <remarks>
    /// The port is included for anything local because that is the part that identifies which
    /// runtime is answering. Two local servers are both "localhost" and only the port says
    /// whether Ollama or LM Studio is about to read the reader's source.
    /// </remarks>
    public static string Describe(Uri endpoint, string? model)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        var host = endpoint.IsLoopback ? $"{endpoint.Host}:{endpoint.Port}" : endpoint.Host;

        return string.IsNullOrWhiteSpace(model) ? host : $"{host} ({model.Trim()})";
    }

    /// <summary>Whether a host with no scheme was meant to be a server on this machine.</summary>
    /// <remarks>
    /// Deliberately the same three names <see cref="Uri.IsLoopback"/> recognises, because
    /// <see cref="OpenAiCompatibleBackend.RejectEndpoint"/> decides whether http is allowed by
    /// asking that property. A name treated as local here and not there would be filled in with
    /// a scheme that is then refused, which is a worse outcome than not helping at all.
    /// </remarks>
    private static bool IsLocalName(string typed)
    {
        if (typed.StartsWith("[::1]", StringComparison.Ordinal))
        {
            return true;
        }

        var host = typed.Split('/', 2)[0].Split(':', 2)[0];

        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host == "127.0.0.1";
    }
}
