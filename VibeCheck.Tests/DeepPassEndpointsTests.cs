using VibeCheck.Core.DeepPass;

namespace VibeCheck.Tests;

/// <summary>
/// The presets, and the tidying that turns what somebody pastes into the URL that is requested.
/// </summary>
/// <remarks>
/// This is a small amount of string handling guarding a failure that is expensive out of all
/// proportion to it: a URL one segment short answers 404 on the first file of the scan, and a 404
/// from a provider the interface offered by name reads as a broken feature rather than as a
/// missing path. The presets are asserted rather than reviewed because none of these paths is
/// this project's to choose, and a provider's is not guessable from the others.
/// </remarks>
public sealed class DeepPassEndpointsTests
{
    // ---- The presets ---------------------------------------------------------

    [Fact]
    public void Every_preset_is_an_address_the_backend_would_accept()
    {
        Assert.NotEmpty(DeepPassEndpoints.Presets);

        foreach (var preset in DeepPassEndpoints.Presets)
        {
            var uri = new Uri(preset.Url, UriKind.Absolute);

            Assert.Null(OpenAiCompatibleBackend.RejectEndpoint(uri));

            // Every one of them is already complete, so offering it changes nothing about it.
            Assert.Equal(uri, DeepPassEndpoints.Normalise(preset.Url));
        }
    }

    [Fact]
    public void Every_preset_points_at_the_chat_completions_path()
    {
        foreach (var preset in DeepPassEndpoints.Presets)
        {
            Assert.EndsWith("/chat/completions", preset.Url, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Local_presets_are_loopback_and_need_no_key()
    {
        var local = DeepPassEndpoints.Presets.Where(p => !p.NeedsKey).ToList();

        // The whole argument for this route over the two Anthropic ones is that there is a
        // configuration in which nothing leaves the machine. If no preset offers it, the reader
        // has to know Ollama's port from memory, which is the problem this list exists to solve.
        Assert.NotEmpty(local);

        foreach (var preset in local)
        {
            Assert.True(new Uri(preset.Url).IsLoopback, preset.Name);
        }
    }

    [Fact]
    public void Hosted_presets_are_encrypted_and_ask_for_a_key()
    {
        foreach (var preset in DeepPassEndpoints.Presets.Where(p => !new Uri(p.Url).IsLoopback))
        {
            Assert.Equal("https", new Uri(preset.Url).Scheme);
            Assert.True(preset.NeedsKey, preset.Name);
        }
    }

    [Fact]
    public void Preset_names_are_distinct()
    {
        var names = DeepPassEndpoints.Presets.Select(p => p.Name).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    /// <summary>
    /// The one preset whose path nobody would guess, pinned on its own.
    /// </summary>
    /// <remarks>
    /// OpenRouter serves from <c>/api/v1</c> and every other provider here from <c>/v1</c>. It
    /// was got wrong once already while this was being built, and the symptom was a 404 that
    /// looked like the feature rather than the address.
    /// </remarks>
    [Fact]
    public void OpenRouter_keeps_its_api_prefix()
    {
        var openRouter = DeepPassEndpoints.Presets.Single(p => p.Name == "OpenRouter");

        Assert.Equal("https://openrouter.ai/api/v1/chat/completions", openRouter.Url);
    }

    // ---- What a reader pastes ------------------------------------------------

    [Theory]

    // The base URL every provider documents, which is not the one a request goes to.
    [InlineData("https://api.openai.com/v1", "https://api.openai.com/v1/chat/completions")]
    [InlineData("https://api.openai.com/v1/", "https://api.openai.com/v1/chat/completions")]
    [InlineData("https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1/chat/completions")]
    [InlineData("https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1/chat/completions")]

    // Already complete, and left alone.
    [InlineData(
        "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/chat/completions")]

    // A bare host is the only case where the version segment is supplied as well.
    [InlineData("https://api.openai.com", "https://api.openai.com/v1/chat/completions")]
    [InlineData("https://api.openai.com/", "https://api.openai.com/v1/chat/completions")]

    // Typed without a scheme. Loopback gets http, which is the one case the backend allows
    // unencrypted; everything else gets https, because the wrong guess in that direction fails
    // to connect rather than sending source code in the clear.
    [InlineData("localhost:11434", "http://localhost:11434/v1/chat/completions")]
    [InlineData("localhost:11434/v1", "http://localhost:11434/v1/chat/completions")]
    [InlineData("127.0.0.1:1234/v1", "http://127.0.0.1:1234/v1/chat/completions")]
    [InlineData("api.openai.com/v1", "https://api.openai.com/v1/chat/completions")]

    // Spaces either side of a paste.
    [InlineData("  https://api.openai.com/v1  ", "https://api.openai.com/v1/chat/completions")]
    public void Completes_what_was_typed_into_what_is_requested(string typed, string expected) =>
        Assert.Equal(expected, DeepPassEndpoints.Normalise(typed)?.ToString());

    [Fact]
    public void Keeps_a_query_string()
    {
        // Some deployments carry a version or a deployment id in the query. Dropping it would
        // turn a working endpoint into a 404 without saying anything.
        var completed = DeepPassEndpoints.Normalise("https://host.example/openai?api-version=2024");

        Assert.Equal(
            "https://host.example/openai/chat/completions?api-version=2024", completed?.ToString());
    }

    [Fact]
    public void Does_not_lose_a_port_on_a_hosted_endpoint()
    {
        Assert.Equal(
            "https://inference.example:8443/v1/chat/completions",
            DeepPassEndpoints.Normalise("https://inference.example:8443/v1")?.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Nothing_typed_is_nothing_configured(string? typed) =>
        Assert.Null(DeepPassEndpoints.Normalise(typed));

    [Fact]
    public void An_unencrypted_endpoint_off_this_machine_is_still_refused()
    {
        // Normalising is not approving. The scheme rule belongs to the backend and the reader is
        // told about it there; this only has to not quietly repair it into something allowed.
        var completed = DeepPassEndpoints.Normalise("http://inference.example/v1");

        Assert.NotNull(completed);
        Assert.NotNull(OpenAiCompatibleBackend.RejectEndpoint(completed));
    }

    // ---- How it is named -----------------------------------------------------

    [Fact]
    public void Describes_a_local_endpoint_by_host_and_port()
    {
        // The port is what says whether Ollama or LM Studio is about to read the source. Both
        // are "localhost" and nothing else distinguishes them.
        Assert.Equal(
            "localhost:11434 (qwen2.5-coder)",
            DeepPassEndpoints.Describe(new Uri("http://localhost:11434/v1/chat/completions"), "qwen2.5-coder"));
    }

    [Fact]
    public void Describes_a_hosted_endpoint_by_host_alone()
    {
        Assert.Equal(
            "openrouter.ai (vendor/model)",
            DeepPassEndpoints.Describe(new Uri("https://openrouter.ai/api/v1/chat/completions"), "vendor/model"));
    }

    [Fact]
    public void Describes_the_destination_without_a_model_when_none_is_wanted()
    {
        Assert.Equal(
            "api.openai.com",
            DeepPassEndpoints.Describe(new Uri("https://api.openai.com/v1/chat/completions"), model: null));
    }
}
