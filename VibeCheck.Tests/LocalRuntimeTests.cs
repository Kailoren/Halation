using System.Net;
using System.Text;

using VibeCheck.Core.DeepPass;

namespace VibeCheck.Tests;

/// <summary>
/// Finding a model runtime already running here, and sizing models against the reader's card.
/// </summary>
/// <remarks>
/// The local route is the only one where recovered source never leaves the machine, so the part
/// that finds it is worth holding still. The sizing half matters for a different reason: the gap
/// between a model that fits in video memory and one that does not is the gap between a scan that
/// takes twenty minutes and one that takes all night, and nobody should discover which they chose
/// by waiting.
/// </remarks>
public sealed class LocalRuntimeTests
{
    /// <summary>Answers the two listing endpoints, and refuses everything else the way a closed port does.</summary>
    private sealed class StubRuntime : HttpMessageHandler
    {
        private readonly Dictionary<string, string> _routes = [];

        public List<string> Asked { get; } = [];

        public void Serve(string url, string json) => _routes[url] = json;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();

            Asked.Add(url);

            if (!_routes.TryGetValue(url, out var body))
            {
                // What a machine with nothing listening actually does.
                throw new HttpRequestException("connection refused");
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    // ---- Finding it ----------------------------------------------------------

    [Fact]
    public async Task Reads_Ollamas_own_listing_because_it_carries_sizes()
    {
        var stub = new StubRuntime();

        stub.Serve(
            "http://localhost:11434/api/tags",
            """
            {"models":[
              {"name":"qwen2.5-coder:7b","size":4683087519},
              {"name":"llama3.1:8b","size":4920753328}
            ]}
            """);

        var found = await LocalRuntimeProbe.FindAsync(stub);

        var ollama = Assert.Single(found);
        Assert.Equal("Ollama", ollama.Name);
        Assert.Equal("http://localhost:11434/v1/chat/completions", ollama.Endpoint.ToString());

        Assert.Equal(2, ollama.Models.Count);
        Assert.Equal("qwen2.5-coder:7b", ollama.Models[0].Id);

        // The size is the entire reason this endpoint is preferred: without it nothing can be
        // said about whether the model fits.
        Assert.Equal(4683087519, ollama.Models[0].Bytes);
    }

    [Fact]
    public async Task Falls_back_to_the_compatible_listing()
    {
        var stub = new StubRuntime();

        stub.Serve(
            "http://localhost:11434/v1/models",
            """{"object":"list","data":[{"id":"qwen2.5-coder:7b","object":"model"}]}""");

        var found = await LocalRuntimeProbe.FindAsync(stub);

        var ollama = Assert.Single(found);
        Assert.Equal("qwen2.5-coder:7b", ollama.Models[0].Id);

        // No size available on this route, and zero is the honest answer rather than a guess.
        Assert.Equal(0, ollama.Models[0].Bytes);
    }

    [Fact]
    public async Task Finds_LM_Studio_on_its_own_port()
    {
        var stub = new StubRuntime();

        stub.Serve(
            "http://localhost:1234/v1/models",
            """{"object":"list","data":[{"id":"qwen2.5-coder-7b-instruct","object":"model"}]}""");

        var found = await LocalRuntimeProbe.FindAsync(stub);

        var studio = Assert.Single(found);
        Assert.Equal("LM Studio", studio.Name);
        Assert.Equal("http://localhost:1234/v1/chat/completions", studio.Endpoint.ToString());
    }

    [Fact]
    public async Task A_running_runtime_with_no_models_is_not_the_same_as_no_runtime()
    {
        var stub = new StubRuntime();

        stub.Serve("http://localhost:11434/api/tags", """{"models":[]}""");

        var found = await LocalRuntimeProbe.FindAsync(stub);

        // Collapsing these two would send somebody off to install what they already have.
        var ollama = Assert.Single(found);
        Assert.Empty(ollama.Models);
    }

    [Fact]
    public async Task Nothing_listening_is_a_normal_answer_rather_than_a_failure()
    {
        var found = await LocalRuntimeProbe.FindAsync(new StubRuntime());

        Assert.Empty(found);
    }

    [Fact]
    public async Task Only_ever_asks_this_machine()
    {
        var stub = new StubRuntime();

        await LocalRuntimeProbe.FindAsync(stub);

        // Nothing here takes a hostname from configuration or from the application being
        // scanned, and this is the assertion that keeps it that way.
        Assert.NotEmpty(stub.Asked);
        Assert.All(stub.Asked, url => Assert.StartsWith("http://localhost:", url, StringComparison.Ordinal));
    }

    // ---- Sizing it -----------------------------------------------------------

    private const long GB = 1024L * 1024 * 1024;

    [Fact]
    public void An_eight_gigabyte_card_is_offered_the_seven_billion_model()
    {
        // The measured case: the machine this was built on. A card that reports 8GB must not be
        // advised to pull a 9GB model, which is the mistake the WMI memory figure would cause.
        var choice = LocalModelGuide.Recommend(8 * GB);

        Assert.NotNull(choice);
        Assert.Equal("qwen2.5-coder:7b", choice.Tag);
    }

    [Theory]
    [InlineData(6, "qwen2.5-coder:3b")]
    [InlineData(8, "qwen2.5-coder:7b")]
    [InlineData(12, "qwen2.5-coder:14b")]
    [InlineData(16, "qwen2.5-coder:14b")]
    [InlineData(24, "qwen2.5-coder:32b")]
    public void Recommends_the_largest_model_that_fits(int gigabytes, string expected) =>
        Assert.Equal(expected, LocalModelGuide.Recommend(gigabytes * GB)?.Tag);

    [Fact]
    public void A_card_too_small_for_any_of_them_gets_no_recommendation()
    {
        // Null rather than the smallest. "It will technically start" is not advice, and dressing
        // it up as one sets somebody up for a scan that runs on the processor all night.
        Assert.Null(LocalModelGuide.Recommend(2 * GB));
        Assert.Contains("none of the suggestions", LocalModelGuide.Advise(2 * GB), StringComparison.Ordinal);
    }

    [Fact]
    public void Says_nothing_about_a_card_it_was_never_told_about()
    {
        Assert.Null(LocalModelGuide.Recommend(0));
        Assert.Equal(ModelFit.Unknown, LocalModelGuide.Judge(4 * GB, 0));
        Assert.Equal(ModelFit.Unknown, LocalModelGuide.Judge(0, 8 * GB));
    }

    [Fact]
    public void Judges_an_installed_model_against_the_card()
    {
        // 4.7GB of weights on an 8GB card, with room left for the file being read.
        Assert.Equal(ModelFit.Comfortable, LocalModelGuide.Judge(4_683_087_519, 8 * GB));

        // 9GB of weights on the same card. It runs, on the processor, slowly.
        Assert.Equal(ModelFit.Spills, LocalModelGuide.Judge(9 * GB, 8 * GB));

        // Fits with nothing spare, which is worth saying rather than calling it comfortable:
        // the context is what pushes this one over.
        Assert.Equal(ModelFit.Tight, LocalModelGuide.Judge(7 * GB, 8 * GB));
    }

    [Theory]
    [InlineData("qwen2.5-coder:7b", true)]
    [InlineData("deepseek-coder-v2:16b", true)]
    [InlineData("codellama:13b", true)]
    [InlineData("codegemma:7b", true)]
    [InlineData("codestral:22b", true)]
    [InlineData("devstral:24b", true)]
    [InlineData("llama3.1:8b", false)]
    [InlineData("mistral-nemo:12b", false)]
    [InlineData("gemma3:12b", false)]
    [InlineData(null, false)]
    public void Recognises_a_model_meant_for_code(string? tag, bool expected) =>
        Assert.Equal(expected, LocalModelGuide.LooksCodeCapable(tag));

    [Fact]
    public void A_general_model_does_not_outrank_a_coder_for_being_slightly_larger()
    {
        // The case that was actually wrong: llama3.1:8b is 4.9GB and qwen2.5-coder:7b is 4.7GB,
        // both fit an 8GB card, and ordering on size alone put the chat model on the row
        // somebody clicks. This is a code review, so the coder wins.
        Assert.True(LocalModelGuide.LooksCodeCapable("qwen2.5-coder:7b"));
        Assert.False(LocalModelGuide.LooksCodeCapable("llama3.1:8b"));

        Assert.Equal(ModelFit.Comfortable, LocalModelGuide.Judge(4_920_753_328, 8 * GB));
        Assert.Equal(ModelFit.Comfortable, LocalModelGuide.Judge(4_683_087_519, 8 * GB));
    }

    [Fact]
    public void Every_suggestion_is_a_code_model()
    {
        // The suggestions are for reading source. One that was not would be advice that
        // contradicts the ordering applied to everything else.
        Assert.All(
            LocalModelGuide.Choices,
            c => Assert.True(LocalModelGuide.LooksCodeCapable(c.Tag), c.Tag));
    }

    [Fact]
    public void Every_suggestion_is_pullable_and_ordered_by_what_it_needs()
    {
        Assert.NotEmpty(LocalModelGuide.Choices);

        long previous = 0;

        foreach (var choice in LocalModelGuide.Choices)
        {
            Assert.StartsWith("ollama pull ", choice.PullCommand, StringComparison.Ordinal);
            Assert.EndsWith(choice.Tag, choice.PullCommand, StringComparison.Ordinal);

            // Smallest first, which Recommend depends on being meaningful and the dialog shows
            // in this order.
            Assert.True(choice.WantsVideoBytes > previous, choice.Tag);
            previous = choice.WantsVideoBytes;

            // A suggestion whose download is larger than the memory it claims to want would be
            // advice that contradicts itself.
            Assert.True(choice.DownloadBytes < choice.WantsVideoBytes, choice.Tag);
        }
    }
}
