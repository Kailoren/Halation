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

        Assert.Contains(
            "none of the suggestions",
            LocalModelGuide.Advise(2 * GB, systemBytes: 0, runtimeNames: null),
            StringComparison.Ordinal);

        // 6GB used to be offered 1.5B and is now told nothing fits, which is the honest answer.
        // Measured 2026-08-06: 1.5B read every qualifying file and returned nothing at all, so
        // recommending it produced a silent all-clear indistinguishable from a clean scan.
        Assert.Null(LocalModelGuide.Recommend(6 * GB));
    }

    [Fact]
    public void No_suggestion_is_small_enough_to_be_useless()
    {
        // The floor the 1.5B measurement established. Anything under a 6GB card gets told that
        // nothing fits rather than being pointed at a size that answers without reading.
        Assert.DoesNotContain(LocalModelGuide.Choices, c => c.Tag.Contains("1.5b", StringComparison.Ordinal));
        Assert.All(LocalModelGuide.Choices, c => Assert.True(c.WantsVideoBytes >= 6 * GB, c.Tag));
    }

    [Fact]
    public void Says_nothing_about_a_card_it_was_never_told_about()
    {
        Assert.Null(LocalModelGuide.Recommend(0));
        Assert.Equal(ModelFit.Unknown, LocalModelGuide.Judge(4 * GB, 0));
        Assert.Equal(ModelFit.Unknown, LocalModelGuide.Judge(0, 8 * GB));
    }

    [Fact]
    public void A_machine_with_no_graphics_card_is_told_it_can_still_do_this()
    {
        var advice = LocalModelGuide.Advise(
            videoBytes: 0,
            systemBytes: 64 * GB,
            runtimeNames: [LocalRuntimeProbe.OllamaName]);

        // It runs on the processor. Saying otherwise, or sending them off to a hosted route,
        // substitutes a judgment about speed for the reason they wanted local in the first
        // place.
        Assert.Contains("processor", advice, StringComparison.Ordinal);
        Assert.Contains("64GB", advice, StringComparison.Ordinal);

        // The reason for the slowness is the actionable part: more memory channels help and
        // more cores do not, so somebody told only "it is slow" would go and buy the wrong
        // thing.
        Assert.Contains("bandwidth rather than core count", advice, StringComparison.Ordinal);

        // And a small model, not the largest that would fit in 64GB of system memory. Without a
        // card the binding constraint is speed rather than capacity, so the advice inverts.
        Assert.Contains("qwen2.5-coder:7b", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("qwen2.5-coder:32b", advice, StringComparison.Ordinal);
    }

    [Fact]
    public void Still_says_something_useful_when_the_memory_is_unknown_too()
    {
        var advice = LocalModelGuide.Advise(videoBytes: 0, systemBytes: 0, runtimeNames: null);

        Assert.Contains("processor", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("0GB", advice, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(LocalRuntimeProbe.OllamaName, "qwen2.5-coder:7b", "qwen/qwen2.5-coder-7b")]
    [InlineData(LocalRuntimeProbe.LmStudioName, "qwen/qwen2.5-coder-7b", "qwen2.5-coder:7b")]
    public void The_advice_names_the_model_the_way_the_detected_runtime_does(
        string runtime,
        string expected,
        string wrong)
    {
        // The defect this fixes: the sentence printed Ollama's tag whatever was running, so an
        // LM Studio reader got "qwen2.5-coder:7b is the largest that fits" directly above a pull
        // command reading "lms get qwen/qwen2.5-coder-7b". Two names for one model on one screen,
        // and the prose named the runtime they had not installed.
        var advice = LocalModelGuide.Advise(8 * GB, systemBytes: 0, runtimeNames: [runtime]);

        Assert.Contains(expected, advice, StringComparison.Ordinal);
        Assert.DoesNotContain(wrong, advice, StringComparison.Ordinal);
    }

    [Fact]
    public void The_advice_names_a_size_rather_than_guessing_a_spelling()
    {
        // Nothing detected, or both runtimes detected, means the reader has not chosen one. Two
        // pull commands are offered below in that case, so the sentence points at them by size
        // instead of picking a spelling that is wrong for half of them.
        foreach (var names in new IEnumerable<string>?[]
                 {
                     null,
                     [],
                     [LocalRuntimeProbe.OllamaName, LocalRuntimeProbe.LmStudioName],
                 })
        {
            var advice = LocalModelGuide.Advise(8 * GB, systemBytes: 0, runtimeNames: names);

            Assert.Contains("the 7B suggestion below", advice, StringComparison.Ordinal);
            Assert.DoesNotContain("qwen", advice, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_processor_advice_names_the_model_the_detected_runtime_way_too()
    {
        // The same bug lived in the no-card sentence, which names the smallest suggestion.
        var advice = LocalModelGuide.Advise(
            videoBytes: 0,
            systemBytes: 64 * GB,
            runtimeNames: [LocalRuntimeProbe.LmStudioName]);

        Assert.Contains("qwen/qwen2.5-coder-7b", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("qwen2.5-coder:7b", advice, StringComparison.Ordinal);
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

    // ---- Cloud models served from a local address ----------------------------

    [Theory]

    // Ollama's own examples. These are served from localhost:11434 like any other model, with
    // the runtime attaching the reader's ollama.com credentials and forwarding the request.
    [InlineData("qwen3-coder:480b-cloud", true)]
    [InlineData("gpt-oss:120b-cloud", true)]
    [InlineData("deepseek-v3.1:671b-cloud", true)]
    [InlineData("gpt-oss:20b-cloud", true)]

    // Trailing whitespace is stripped before the check, because this decides whether the
    // interface claims nothing was uploaded.
    [InlineData("gpt-oss:120b-cloud  ", true)]
    [InlineData("QWEN3-CODER:480B-CLOUD", true)]

    // Ordinary local models, including one whose name merely contains the word.
    [InlineData("qwen2.5-coder:7b", false)]
    [InlineData("cloud-atlas:7b", false)]
    [InlineData("llama3.1:8b", false)]
    [InlineData(null, false)]
    public void Recognises_a_model_that_is_not_on_this_machine(string? tag, bool expected) =>
        Assert.Equal(expected, LocalModelGuide.IsCloudModel(tag));

    [Fact]
    public void A_cloud_model_reports_no_size_and_must_not_be_judged_as_local()
    {
        // Ollama lists cloud models with a dash in the size column, which reaches the API as no
        // size at all. Nothing about that should read as a model that happens to fit.
        Assert.Equal(ModelFit.Unknown, LocalModelGuide.Judge(0, 8 * GB));

        // And the name is the only other signal available, so it has to be the load-bearing one.
        Assert.True(LocalModelGuide.IsCloudModel("qwen3-coder:480b-cloud"));
        Assert.True(LocalModelGuide.LooksCodeCapable("qwen3-coder:480b-cloud"));
    }

    [Fact]
    public void No_suggestion_carries_a_research_only_licence()
    {
        // Qwen publishes this family under Apache 2.0 at every size except 3B, which is under
        // its research licence. Nothing is distributed here, but a reader scanning their own
        // commercial application should not be pointed at a model they may not use for it.
        Assert.DoesNotContain(LocalModelGuide.Choices, c => c.Tag.Contains(":3b", StringComparison.Ordinal));
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
            // Each runtime gets its own command and its own spelling of the model. Neither
            // accepts the other's, so a single command was wrong for one of the two readers.
            var ollama = choice.PullCommandFor(LocalRuntimeProbe.OllamaName);
            var lmStudio = choice.PullCommandFor(LocalRuntimeProbe.LmStudioName);

            Assert.StartsWith("ollama pull ", ollama, StringComparison.Ordinal);
            Assert.EndsWith(choice.Tag, ollama, StringComparison.Ordinal);

            Assert.StartsWith("lms get ", lmStudio, StringComparison.Ordinal);
            Assert.EndsWith(choice.LmStudioTag, lmStudio, StringComparison.Ordinal);

            // The two spellings must actually differ, or one of them is a copied placeholder.
            Assert.NotEqual(choice.Tag, choice.LmStudioTag);

            // An unknown or absent runtime falls back to Ollama rather than to nothing, since
            // that is the older and more widely installed of the two.
            Assert.Equal(ollama, choice.PullCommandFor(null));

            // Smallest first, which Recommend depends on being meaningful and the dialog shows
            // in this order.
            Assert.True(choice.WantsVideoBytes > previous, choice.Tag);
            previous = choice.WantsVideoBytes;

            // A suggestion whose download is larger than the memory it claims to want would be
            // advice that contradicts itself.
            Assert.True(choice.DownloadBytes < choice.WantsVideoBytes, choice.Tag);

            // The size has to survive as far as something a reader can read. It was carried on
            // every choice and displayed nowhere for two releases, which is how a figure that
            // disagreed with the installed one went unnoticed.
            Assert.True(choice.DownloadBytes > 0, choice.Tag);
            Assert.NotEqual("size unknown", LocalModelGuide.Gigabytes(choice.DownloadBytes));
        }
    }

    [Fact]
    public void A_suggestion_is_sized_the_same_before_and_after_it_is_installed()
    {
        // The defect this pins: the download sizes were Ollama's decimal gigabytes written into a
        // field rendered as binary ones, so the 7B read 4.7GB as a suggestion and 4.4GB once
        // installed. Judge and the suggestion table have to agree, or the dialog contradicts
        // itself across a single pull.
        var seven = LocalModelGuide.Choices.Single(c => c.Tag == "qwen2.5-coder:7b");

        // The real manifest total, which is also what /api/tags reports once it is on disk.
        const long Installed = 4_683_087_074;

        Assert.Equal(
            LocalModelGuide.Gigabytes(Installed),
            LocalModelGuide.Gigabytes(seven.DownloadBytes));

        // And the verdict has to match too: an 8GB card is the case this size exists for.
        Assert.Equal(ModelFit.Comfortable, LocalModelGuide.Judge(seven.DownloadBytes, 8 * GB));
    }

    /// <summary>
    /// The context advice names the runtime that is answering, because the two set it in
    /// completely different places.
    /// </summary>
    /// <remarks>
    /// The defect this pins: the caution was Ollama's environment variable unconditionally, so a
    /// reader running LM Studio was told to set a variable it never reads, on the same screen
    /// that had correctly identified LM Studio as the one running.
    /// </remarks>
    [Fact]
    public void The_context_caution_names_the_runtime_that_answered()
    {
        var ollama = LocalModelGuide.ContextCautionFor([LocalRuntimeProbe.OllamaName]);

        Assert.Contains("OLLAMA_CONTEXT_LENGTH", ollama, StringComparison.Ordinal);
        Assert.DoesNotContain("LM Studio", ollama, StringComparison.Ordinal);

        var lmStudio = LocalModelGuide.ContextCautionFor([LocalRuntimeProbe.LmStudioName]);

        Assert.Contains("LM Studio", lmStudio, StringComparison.Ordinal);
        Assert.DoesNotContain("OLLAMA_CONTEXT_LENGTH", lmStudio, StringComparison.Ordinal);

        // Nothing detected means the reader has not chosen yet, so both are named rather than
        // one being guessed at.
        foreach (var undecided in new[]
                 {
                     LocalModelGuide.ContextCautionFor(null),
                     LocalModelGuide.ContextCautionFor([]),
                     LocalModelGuide.ContextCautionFor(
                         [LocalRuntimeProbe.OllamaName, LocalRuntimeProbe.LmStudioName]),
                 })
        {
            Assert.Contains("OLLAMA_CONTEXT_LENGTH", undecided, StringComparison.Ordinal);
            Assert.Contains("LM Studio", undecided, StringComparison.Ordinal);
        }
    }
}
