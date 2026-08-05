using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;

using VibeCheck.Core;
using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;
using VibeCheck.Core.Rules;

namespace VibeCheck.App;

public enum AppState
{
    /// <summary>
    /// The one-time question about who is reading. Ahead of Waiting because the answer
    /// changes what a scan means, not merely how it looks, so there is no useful scan to
    /// offer before it is answered.
    /// </summary>
    ChoosingAudience,
    Waiting,
    Scanning,
    Results,
}

/// <summary>
/// Which of the three things answers the deep pass.
/// </summary>
/// <remarks>
/// One value rather than a set of interlocking flags. It began as a pair of booleans that were
/// each other's inverse, which worked for two options and does not survive a third: three flags
/// have eight states and five of them are nonsense.
/// </remarks>
public enum DeepPassSource
{
    /// <summary>An Anthropic key the reader bought. Costs money, per file read.</summary>
    ApiKey,

    /// <summary>Claude Code on this machine. Costs subscription quota, not money.</summary>
    LocalCli,

    /// <summary>Any chat-completions endpoint, hosted or on this machine.</summary>
    Endpoint,
}

/// <summary>Drives the whole window. Deliberately one view model; the app has three screens.</summary>
public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly Scanner _scanner = new();
    private CancellationTokenSource? _cancellation;

    // Asked on every launch, not only the first. Which question you want answered is a
    // property of the artifact about to be checked rather than a fixed fact about the person:
    // the same reader audits their own build one day and something they downloaded the next.
    // The stored value is a starting point for the question, never a reason to skip it.
    private AppState _state = AppState.ChoosingAudience;

    private Audience _audience = AudienceStore.Load() ?? Audience.Developer;
    private string _progressMessage = string.Empty;
    private int _progressPercent;
    private bool _isDragging;
    private bool _isMinimised;
    private string? _error;
    private ScanReport? _report;

    public MainViewModel()
    {
        ScanCommand = new RelayCommand(_ => { }, _ => false);
        CancelCommand = new RelayCommand(_ => _cancellation?.Cancel(), _ => State == AppState.Scanning);
        ResetCommand = new RelayCommand(_ => Reset(), _ => State != AppState.Scanning);
        ExportMarkdownCommand = new RelayCommand(_ => Export("md"), _ => Report is not null);
        ExportJsonCommand = new RelayCommand(_ => Export("json"), _ => Report is not null);
        ChooseAudienceCommand = new RelayCommand(a => ChooseAudience(a as string));
        SwitchAudienceCommand = new RelayCommand(_ => Audience =
            Audience == Audience.EndUser ? Audience.Developer : Audience.EndUser);

        // Back to the opening question rather than only the inline toggle. Which reader a scan
        // is for changes what the scan does, not just how it reads, so it is worth a way back
        // to the screen that explains the difference.
        ReturnToSelectionCommand = new RelayCommand(
            _ => State = AppState.ChoosingAudience,
            _ => State != AppState.Scanning);

        SignInToClaudeCodeCommand = new RelayCommand(
            _ => _ = SignInToClaudeCodeAsync(),
            _ => SignInEnabled);

        // Started, not awaited. The answer only decides whether one option is offerable, and
        // the audience question is on screen first regardless; the status line says it is
        // still looking until it knows.
        _ = DetectLocalCliAsync();
    }

    // ---- Who is reading ----------------------------------------------------

    /// <summary>
    /// Which of the two reports this person gets. Changing it re-renders the findings from
    /// the report already in hand, so switching does not mean rescanning: the severities for
    /// both readers were computed during the scan.
    /// </summary>
    public Audience Audience
    {
        get => _audience;
        set
        {
            if (!Set(ref _audience, value))
            {
                return;
            }

            AudienceStore.Save(value);
            Notify(nameof(IsEndUser));
            Notify(nameof(AudienceSummary));
            Notify(nameof(SwitchAudienceLabel));

            // Switching to the end user view withdraws the deep pass entirely, because that
            // view means the reader did not write what they are about to scan. Selecting a
            // source and then changing audience must not leave the choice standing.
            Notify(nameof(LocalCliReady));
            Notify(nameof(LocalCliStatus));
            Notify(nameof(CanRunDeepPass));
            Notify(nameof(DeepPassOfferedHere));
            Notify(nameof(DeepPassSourceReady));

            if (_deepPassSource == DeepPassSource.LocalCli && !LocalCliReady)
            {
                ChooseSource(HasEndpoint ? DeepPassSource.Endpoint : DeepPassSource.ApiKey);
            }

            if (_deepPassEnabled && !DeepPassSourceReady)
            {
                _deepPassEnabled = false;
                Notify(nameof(DeepPassEnabled));
                NotifyDeepPassState();
            }

            // The number itself will not move, being the worse of both readings either way,
            // but every finding's severity, wording and position does, and the account under
            // the score names whichever reading governed. All of that is rebuilt from the
            // report already in hand rather than rescanned.
            if (Report is not null)
            {
                Report = Scanner.Rescore(Report, value);
            }
        }
    }

    public ICommand ChooseAudienceCommand { get; }

    public ICommand SwitchAudienceCommand { get; }

    public ICommand ReturnToSelectionCommand { get; }

    public string SwitchAudienceLabel => Audience == Audience.EndUser
        ? "Switch to the developer view"
        : "Switch to the end user view";

    public bool IsChoosingAudience => State == AppState.ChoosingAudience;

    public bool IsEndUser => Audience == Audience.EndUser;

    /// <summary>Shown on the results screen so the reader knows which report they are in.</summary>
    public string AudienceSummary => Audience == Audience.EndUser
        ? "Written for someone deciding whether to run this. Switch to the developer view for "
          + "rule identifiers, advisory links, and how to fix each finding."
        : "Written for whoever ships this. Switch to the end user view to see what someone "
          + "who downloaded it would be told.";

    private void ChooseAudience(string? name)
    {
        if (!Enum.TryParse<Audience>(name, out var audience))
        {
            return;
        }

        Audience = audience;
        AudienceStore.Save(audience);

        if (State == AppState.ChoosingAudience)
        {
            State = AppState.Waiting;
        }
    }

    // ---- Deep pass ---------------------------------------------------------

    private bool _deepPassEnabled;
    private DeepPassSource _deepPassSource;
    private DeepPassEndpointSettings? _endpoint = EndpointStore.Load();
    private ClaudeCodeCli? _localCli;
    private bool _localCliSignedIn;
    private bool _localCliSearched;

    /// <summary>
    /// Whether this scan runs the optional deep pass. Off by default and not remembered
    /// between runs: it spends something of the reader's either way, so it should be a
    /// decision each time rather than a setting that quietly stays on.
    /// </summary>
    public bool DeepPassEnabled
    {
        get => _deepPassEnabled;
        set
        {
            if (!Set(ref _deepPassEnabled, value))
            {
                return;
            }

            // Turning it on moves to a source that can answer rather than refusing the tick.
            // Refusing was the old behaviour and it made the checkbox useless: the API key
            // route is selected by default, so a reader with no key but a working Claude Code
            // install found the box would not stay ticked, with nothing on screen saying why.
            // They had to discover that picking the other option first was the real action,
            // which left the checkbox doing nothing at all.
            //
            // A configured endpoint is preferred first, in the same order DeepPassRunner uses.
            // Nominating one is the most specific instruction of the three, and somebody who
            // set up a local model must not be quietly answered by a subscription that sends
            // their code somewhere they deliberately chose not to send it.
            if (value && !DeepPassSourceReady)
            {
                if (HasEndpoint)
                {
                    ChooseSource(DeepPassSource.Endpoint);
                }
                else if (LocalCliReady)
                {
                    ChooseSource(DeepPassSource.LocalCli);
                }
                else if (HasApiKey)
                {
                    ChooseSource(DeepPassSource.ApiKey);
                }
            }

            // Still nothing available. Untick rather than claim a pass that will not happen.
            if (value && !DeepPassSourceReady)
            {
                Set(ref _deepPassEnabled, false);
                Notify(nameof(DeepPassEnabled));
            }

            NotifyDeepPassState();
        }
    }

    /// <summary>
    /// Whether each source choice is live.
    /// </summary>
    /// <remarks>
    /// Setting a key or an endpoint stays reachable whether or not the pass is on: that is
    /// configuration rather than part of this scan, and gating it would leave someone with
    /// nothing configured unable to reach the control that would configure something. Only the
    /// choice between ready sources is gated.
    /// </remarks>
    public bool CanChooseApiKey => DeepPassEnabled && HasApiKey;

    public bool CanChooseLocalCli => DeepPassEnabled && LocalCliReady;

    public bool CanChooseEndpoint => DeepPassEnabled && HasEndpoint;

    /// <summary>
    /// The three radio buttons, one property each.
    /// </summary>
    /// <remarks>
    /// Read from one enum rather than held as three flags. Setting only acts on true because
    /// WPF clears the outgoing button as well as setting the incoming one, and honouring the
    /// clear would mean the group briefly had no answer.
    /// </remarks>
    public bool DeepPassUsesApiKey
    {
        get => _deepPassSource == DeepPassSource.ApiKey;
        set
        {
            if (value)
            {
                ChooseSource(DeepPassSource.ApiKey);
            }
        }
    }

    public bool DeepPassUsesLocalCli
    {
        get => _deepPassSource == DeepPassSource.LocalCli;
        set
        {
            if (value)
            {
                ChooseSource(DeepPassSource.LocalCli);
            }
        }
    }

    public bool DeepPassUsesEndpoint
    {
        get => _deepPassSource == DeepPassSource.Endpoint;
        set
        {
            if (value)
            {
                ChooseSource(DeepPassSource.Endpoint);
            }
        }
    }

    /// <summary>
    /// Moves the pass to a different source, and withdraws it if that source cannot answer.
    /// </summary>
    /// <remarks>
    /// Each source has its own reasons for being unavailable, so a change of source can
    /// invalidate a pass that was valid a moment ago. Silently leaving the tick would promise a
    /// deep pass that the scan then declines to run.
    /// </remarks>
    private void ChooseSource(DeepPassSource source)
    {
        if (_deepPassSource == source)
        {
            return;
        }

        _deepPassSource = source;

        Notify(nameof(DeepPassUsesApiKey));
        Notify(nameof(DeepPassUsesLocalCli));
        Notify(nameof(DeepPassUsesEndpoint));
        NotifyDeepPassState();

        if (_deepPassEnabled && !DeepPassSourceReady)
        {
            _deepPassEnabled = false;
            Notify(nameof(DeepPassEnabled));
            NotifyDeepPassState();
        }
    }

    /// <summary>
    /// Everything that depends on which source is chosen and whether the pass is on.
    /// </summary>
    /// <remarks>
    /// Kept in one place because the list grew a third entry and the notifications were
    /// duplicated across five setters. A property missing from one copy is a line of the
    /// interface that goes stale while the rest updates, which reads as the wrong sentence
    /// rather than as a bug.
    /// </remarks>
    private void NotifyDeepPassState()
    {
        Notify(nameof(PrivacyLine));
        Notify(nameof(NetworkSummary));
        Notify(nameof(DeepPassCostLine));
        Notify(nameof(DeepPassDestinationLine));
        Notify(nameof(CanChooseApiKey));
        Notify(nameof(CanChooseLocalCli));
        Notify(nameof(CanChooseEndpoint));
    }

    public bool HasApiKey => ApiKeyStore.Load() is not null;

    /// <summary>Whether an endpoint has been configured for this machine.</summary>
    public bool HasEndpoint => _endpoint is not null;

    /// <summary>
    /// What is stored, for the dialog that edits it. Not bound to by anything on this screen.
    /// </summary>
    /// <remarks>
    /// This carries the key, which is otherwise never handed out. The dialog needs to know one
    /// exists in order to decide what an empty field means, and that is a different thing from
    /// displaying it: nothing renders this, and the dialog puts it back only when the endpoint
    /// it belongs to is unchanged.
    /// </remarks>
    public DeepPassEndpointSettings? Endpoint => _endpoint;

    /// <summary>
    /// The configured endpoint, named by where the code would go rather than by provider.
    /// </summary>
    /// <remarks>
    /// The host and the model, because those are the two facts that decide what happens: one
    /// says whose machine reads the source and the other says what it is read by. Nobody can
    /// infer either from anywhere else on this screen.
    /// </remarks>
    public string EndpointStatus => _endpoint?.Description ?? "not configured";

    /// <summary>
    /// Why the endpoint route is or is not available, in the same place the other two routes
    /// say it.
    /// </summary>
    /// <remarks>
    /// Says whether it is on this machine, which is the one fact that distinguishes this route
    /// from the other two rather than merely from another provider. Everything else about it is
    /// the reader's own configuration and needs no explaining back to them.
    /// </remarks>
    public string EndpointSourceStatus => _endpoint is null
        ? "Not configured. Use Configure above to name one, including a model on this machine."
        : _endpoint.Description + (_endpoint.IsLocal ? ", on this machine." : ".");

    /// <summary>Whether the chosen source reads the files without them leaving this computer.</summary>
    /// <remarks>
    /// True only for a local model behind a loopback endpoint. Both Anthropic routes upload,
    /// and so does a hosted endpoint, so this is the one configuration in which switching the
    /// deep pass on does not change what leaves the machine.
    /// </remarks>
    public bool DeepPassStaysLocal =>
        _deepPassSource == DeepPassSource.Endpoint && _endpoint?.IsLocal == true;

    /// <summary>
    /// Whether the deep pass is offered to this reader at all.
    /// </summary>
    /// <remarks>
    /// Developer view only, and a product decision rather than a security one: the API endpoint
    /// cannot execute anything, but somebody checking a download is asking whether to trust it,
    /// and an answer costing money and an account is not what that question wants. The core
    /// still permits an API-backed pass for either audience.
    /// </remarks>
    public bool DeepPassOfferedHere => Audience == Audience.Developer;

    /// <summary>Whether the source currently chosen can actually answer.</summary>
    public bool DeepPassSourceReady => DeepPassOfferedHere && _deepPassSource switch
    {
        DeepPassSource.LocalCli => LocalCliReady,
        DeepPassSource.Endpoint => HasEndpoint,
        _ => HasApiKey,
    };

    /// <summary>Whether anything at all could answer, which is what gates the checkbox.</summary>
    public bool CanRunDeepPass =>
        DeepPassOfferedHere && (HasApiKey || LocalCliReady || HasEndpoint);

    /// <summary>
    /// Shown in place of the controls when the pass is not on offer, rather than leaving a row
    /// of dead controls for somebody to click at and get nothing from.
    /// </summary>
    public string DeepPassUnavailableHere =>
        "Only available in developer mode, for an app you made. Checking something you "
        + "downloaded runs entirely on this machine.";

    /// <summary>
    /// Whether the local agent route is offerable.
    /// </summary>
    /// <remarks>
    /// The audience is part of the test rather than presentation: Claude Code can act on this
    /// machine and the API cannot. The core refuses regardless; this only decides whether the
    /// option is offered or explained.
    /// </remarks>
    public bool LocalCliReady =>
        _localCli is not null && _localCliSignedIn && Audience == Audience.Developer;

    /// <summary>Why the local route is or is not available, in something the reader can act on.</summary>
    public string LocalCliStatus => (_localCliSearched, _localCli, _localCliSignedIn) switch
    {
        (false, _, _) => "Looking for Claude Code on this machine...",

        (_, null, _) => "Not found on this machine. Install Claude Code to use this option.",

        (_, _, false) => IsSigningIn
            ? "Signing in. Finish in the window that opened, then come back here."
            : "Found, but not signed in.",

        _ when Audience != Audience.Developer =>
            "Only offered when reporting for whoever ships this. Claude Code can act on this "
            + "computer, so it is not pointed at software you did not write.",

        _ => _localCli!.Description,
    };

    /// <summary>
    /// Whether to offer the sign-in button: Claude Code is here, it just has no credential.
    /// </summary>
    public bool CanSignInToClaudeCode =>
        _localCliSearched && _localCli is not null && !_localCliSignedIn;

    private bool _isSigningIn;

    /// <summary>True while the sign-in window is open, so the button cannot be pressed twice.</summary>
    public bool IsSigningIn
    {
        get => _isSigningIn;
        private set
        {
            if (Set(ref _isSigningIn, value))
            {
                Notify(nameof(LocalCliStatus));
                Notify(nameof(SignInEnabled));
            }
        }
    }

    public bool SignInEnabled => CanSignInToClaudeCode && !IsSigningIn;

    public ICommand SignInToClaudeCodeCommand { get; }

    /// <summary>
    /// Runs the CLI's own interactive sign-in, then re-checks.
    /// </summary>
    /// <remarks>
    /// The credential never passes through this application: Claude Code opens its own browser
    /// flow and VibeCheck learns only what <c>auth status</c> says afterwards. The arguments are
    /// a fixed literal and the only variable is the executable path, which came from the
    /// locator. <c>UseShellExecute</c> is on because an interactive sign-in needs a console.
    /// </remarks>
    private async Task SignInToClaudeCodeAsync()
    {
        if (_localCli is not { } cli || IsSigningIn)
        {
            return;
        }

        IsSigningIn = true;

        try
        {
            using var process = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo
                {
                    FileName = cli.Path,
                    Arguments = "auth login --claudeai",
                    UseShellExecute = true,
                });

            if (process is not null)
            {
                await process.WaitForExitAsync().ConfigureAwait(true);
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
                                      or InvalidOperationException or IOException)
        {
            Error = "Could not start Claude Code to sign in. Run \"claude auth login\" in a "
                    + "terminal instead.";
        }
        finally
        {
            IsSigningIn = false;
        }

        // Re-asked rather than assumed. Closing the window is not the same as completing the
        // sign-in, and a reader who cancelled must not be shown a route that will fail.
        _localCliSearched = false;
        await DetectLocalCliAsync().ConfigureAwait(true);
    }

    /// <summary>What the chosen source spends, said plainly next to the choice.</summary>
    /// <remarks>
    /// The endpoint route deliberately declines to name a figure. What a request costs there
    /// depends on a price list this application has never seen, and a scanner whose entire value
    /// is that it does not state things it cannot check should not begin by stating a price it
    /// guessed. <see cref="OpenAiCompatibleBackend"/> takes the same position in the report.
    /// </remarks>
    public string DeepPassCostLine => _deepPassSource switch
    {
        DeepPassSource.LocalCli =>
            "Spends your Claude subscription's quota. Nothing is charged to you.",

        DeepPassSource.Endpoint when DeepPassStaysLocal =>
            "Runs on your own hardware. Nothing is charged and nothing is uploaded.",

        DeepPassSource.Endpoint =>
            "Billed by whoever runs that endpoint, at rates VibeCheck has no way to know. The "
            + "report states the tokens spent rather than inventing what they cost.",

        _ => "Billed to your Anthropic API key, per file read.",
    };

    /// <summary>
    /// What each route does, on hover: where the code goes, what it costs, what it needs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same three facts in the same order in all three, so that moving the pointer from one
    /// option to the next compares like with like. They are the questions somebody actually has
    /// when choosing, and the card has room for one line about the route already selected, which
    /// is no use at the moment of choosing between them.
    /// </para>
    /// <para>
    /// <b>The first fact is deliberately the destination rather than the price.</b> Two of these
    /// three routes upload the reader's recovered source and one does not, and that difference
    /// is easy to miss when the visible difference is the billing. "Claude Code on this machine"
    /// in particular reads as local and is not: the program is local, the reading is not.
    /// </para>
    /// <para>
    /// Shown on the disabled radios too, through <c>ToolTipService.ShowOnDisabled</c>. A route is
    /// disabled exactly when it has not been set up, which is precisely when somebody wants to
    /// know what setting it up would get them.
    /// </para>
    /// </remarks>
    public string ApiKeyRouteTooltip =>
        "Where your code goes: to Anthropic, over the internet.\n\n"
        + "What it costs: your API key is billed for every file read, on every scan. Tens of "
        + "cents for a small application, a few dollars for a large one.\n\n"
        + "What you need: a key from console.anthropic.com. Nothing to install.\n\n"
        + "This route runs Claude Opus 5, the most capable of the three, so it finds the most.";

    public string LocalCliRouteTooltip =>
        "Where your code goes: to Anthropic, the same as the key route. Claude Code is installed "
        + "on this machine, but the reading does not happen here.\n\n"
        + "What it costs: quota from the Claude subscription you already pay for. Nothing is "
        + "charged, and nothing is billed per scan.\n\n"
        + "What you need: Claude Code installed and signed in.\n\n"
        + "Offered only for an application you built yourself, because Claude Code can act on "
        + "this computer and an API endpoint cannot.";

    /// <summary>
    /// The third route, which is the only one whose answer depends on how it was configured.
    /// </summary>
    /// <remarks>
    /// Asks <c>_endpoint</c> directly rather than going through
    /// <see cref="DeepPassStaysLocal"/>, which is only true once this route is the selected one.
    /// A tooltip describes what an option would do, and is read before it is chosen.
    /// </remarks>
    public string EndpointRouteTooltip => _endpoint switch
    {
        null =>
            "Any server that speaks the OpenAI chat-completions format: OpenAI, OpenRouter, "
            + "Gemini, Groq and others, or Ollama and LM Studio running on this machine.\n\n"
            + "Pointed at this machine, it is the only route where your code never leaves it: "
            + "no upload, no account, no bill, and it works with the network unplugged.\n\n"
            + "Nothing is configured yet. Use Configure above.",

        { IsLocal: true } =>
            $"Where your code goes: nowhere. {EndpointHost} is this computer talking to itself, "
            + "so the files never reach the network.\n\n"
            + "What it costs: nothing but electricity.\n\n"
            + "What you need: Ollama or LM Studio running, with a model downloaded.\n\n"
            + "A model on your own machine is smaller than Claude Opus 5 and will find less. The "
            + "report names what answered, so a quiet result can be read for what it is.",

        _ =>
            $"Where your code goes: to {EndpointHost}, over an encrypted connection. VibeCheck "
            + "knows nothing about what happens to it there.\n\n"
            + "What it costs: whatever that provider charges. VibeCheck has no way to know their "
            + "prices, so the report states the tokens spent rather than inventing a figure.\n\n"
            + "What you need: the endpoint, a model id, and usually a key.\n\n"
            + "Point this same route at Ollama or LM Studio instead and nothing leaves this "
            + "machine at all.",
    };

    /// <summary>
    /// Where the selected files go and what happens to them, beneath the source choice.
    /// </summary>
    /// <remarks>
    /// Bound rather than fixed because it used to be a fixed sentence saying both routes went to
    /// Anthropic, which stopped being true the moment a third route existed. A paragraph that
    /// keeps asserting a destination the reader has just changed is worse than no paragraph:
    /// they have no reason to doubt it.
    /// </remarks>
    public string DeepPassDestinationLine =>
        "Only the files that handle untrusted input are sent, never the whole application. "
        + _deepPassSource switch
        {
            DeepPassSource.LocalCli =>
                "They go to Anthropic through Claude Code, on your subscription. ",

            DeepPassSource.Endpoint when DeepPassStaysLocal =>
                $"They go to the model at {EndpointHost} and no further: nothing leaves this "
                + "computer. ",

            DeepPassSource.Endpoint when _endpoint is not null =>
                $"They go to {EndpointHost}, over an encrypted connection, and this application "
                + "knows nothing else about what happens to them there. ",

            DeepPassSource.Endpoint => string.Empty,

            _ => "They go to Anthropic on your key. ",
        }
        + "Keys you set are encrypted to your Windows account and stored outside the "
        + "application folder. The report names which files were read and what answered.";

    /// <summary>
    /// The standing promise on the drop screen, which stops being true the moment the deep
    /// pass is switched on. Leaving "nothing is uploaded" showing while source is about to be
    /// sent to an API would be the plainest possible lie this interface could tell.
    /// </summary>
    /// <remarks>
    /// Both Anthropic routes upload, and so does a hosted endpoint. Only a model on this machine
    /// leaves the promise standing, so only that case is allowed to keep saying so.
    /// </remarks>
    public string PrivacyLine => DeepPassEnabled
        ? _deepPassSource switch
        {
            DeepPassSource.LocalCli =>
                "Deep pass is on: the files it selects will be sent to Anthropic through Claude "
                + "Code, on your subscription. Everything else runs on this machine.",

            DeepPassSource.Endpoint when DeepPassStaysLocal =>
                $"Deep pass is on, answered by the model at {EndpointHost}. Nothing is uploaded: "
                + "all of it runs on this machine.",

            DeepPassSource.Endpoint when _endpoint is not null =>
                $"Deep pass is on: the files it selects will be sent to {EndpointHost}. "
                + "Everything else runs on this machine.",

            DeepPassSource.Endpoint =>
                "Deep pass is on: the files it selects will be sent to the endpoint you "
                + "configure. Everything else runs on this machine.",

            _ => "Deep pass is on: the files it selects will be sent to Anthropic on your key. "
                 + "Everything else runs on this machine.",
        }
        : "Nothing is uploaded. Analysis runs on this machine.";

    /// <summary>
    /// What leaves this machine, in one line, for the status bar.
    /// </summary>
    /// <remarks>
    /// The compact form of <see cref="PrivacyLine"/>, which is the claim this application is
    /// built around and which until now vanished the moment a scan finished: it appears on the
    /// drop screen and nowhere else, so the reader was told what was uploaded only while there
    /// was nothing to upload. Kept true rather than reassuring, so switching the deep pass on
    /// changes it, and a deep pass answered on this machine leaves it alone.
    /// </remarks>
    public string NetworkSummary =>
        DeepPassEnabled && DeepPassSourceReady && !DeepPassStaysLocal
            ? "Runs on this machine  ·  package names and the deep pass's files leave it"
            : "Runs on this machine  ·  only package names leave it";

    public string ApiKeyStatus => ApiKeyStore.Describe(ApiKeyStore.Load());

    /// <summary>Just the destination, for sentences that have already said what is sent.</summary>
    private string EndpointHost =>
        _endpoint is null ? "that endpoint" : DeepPassEndpoints.Describe(_endpoint.Endpoint, null);

    /// <summary>Stores or clears the key, then refreshes everything that depends on it.</summary>
    public void SetApiKey(string? key)
    {
        ApiKeyStore.Save(key);

        if (!DeepPassSourceReady)
        {
            _deepPassEnabled = false;
        }

        Notify(nameof(HasApiKey));
        Notify(nameof(ApiKeyStatus));
        Notify(nameof(CanRunDeepPass));
        Notify(nameof(DeepPassEnabled));
        NotifyDeepPassState();
    }

    /// <summary>Stores or clears the endpoint, then refreshes everything that depends on it.</summary>
    /// <remarks>
    /// Removing the endpoint that was about to answer withdraws the pass rather than falling
    /// back to a key, on the same reasoning the runner uses: somebody who set up a local model
    /// and then removed it has not thereby asked for their code to be sent to Anthropic instead.
    /// </remarks>
    public void SetEndpoint(DeepPassEndpointSettings? settings)
    {
        EndpointStore.Save(settings);
        _endpoint = settings;

        if (!DeepPassSourceReady)
        {
            _deepPassEnabled = false;
        }

        Notify(nameof(HasEndpoint));
        Notify(nameof(EndpointStatus));
        Notify(nameof(EndpointSourceStatus));
        Notify(nameof(EndpointRouteTooltip));
        Notify(nameof(DeepPassStaysLocal));
        Notify(nameof(CanRunDeepPass));
        Notify(nameof(DeepPassEnabled));
        NotifyDeepPassState();
    }

    /// <summary>
    /// Looks for a usable Claude Code installation, off the UI thread.
    /// </summary>
    /// <remarks>
    /// Installed and signed in are separate facts and the second costs a process launch, so it
    /// happens once at startup rather than when the scan button is pressed. Finding nothing is a
    /// normal outcome, reported in the status line and never as an error.
    /// </remarks>
    private async Task DetectLocalCliAsync()
    {
        try
        {
            var cli = await Task.Run(() => ClaudeCodeCliLocator.Locate()).ConfigureAwait(true);

            if (cli is not null)
            {
                var auth = await Task.Run(() => ClaudeCodeCliBackend.CheckAuthenticationAsync(cli))
                    .ConfigureAwait(true);

                _localCliSignedIn = auth.SignedIn;
            }

            _localCli = cli;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException
                                      or UnauthorizedAccessException)
        {
            _localCli = null;
        }
        finally
        {
            _localCliSearched = true;

            // Marshalled explicitly rather than relying on the await resuming on the UI thread.
            // It usually does, because a dispatcher synchronisation context is installed once
            // Application.Run is pumping, but this starts from a constructor that can run
            // before that is true, and then the continuation resumes on the thread pool.
            var dispatcher = System.Windows.Application.Current?.Dispatcher;

            if (dispatcher is not null && !dispatcher.CheckAccess())
            {
                dispatcher.Invoke(NotifyLocalCliState);
            }
            else
            {
                NotifyLocalCliState();
            }
        }
    }

    private void NotifyLocalCliState()
    {
        Notify(nameof(LocalCliReady));
        Notify(nameof(LocalCliStatus));
        Notify(nameof(CanRunDeepPass));
        Notify(nameof(CanChooseLocalCli));
        Notify(nameof(CanSignInToClaudeCode));
        Notify(nameof(SignInEnabled));
        CommandManager.InvalidateRequerySuggested();
    }

    /// <summary>The build's own version, shown in the title bar and stamped into reports.</summary>
    /// <remarks>An instance property, not a static one: WPF resolves binding paths against
    /// the DataContext instance and would silently find nothing on a static.</remarks>
    public string Version => Scanner.Version;

    /// <summary>
    /// Whether a newer build has been published, and what can be done about it.
    /// </summary>
    /// <remarks>
    /// Separate from everything above it because none of it concerns a scan. It is exposed here
    /// only because the window binds to one object.
    /// </remarks>
    public UpdateViewModel Update { get; } = new();

    // ---- State -------------------------------------------------------------

    public AppState State
    {
        get => _state;
        private set
        {
            if (Set(ref _state, value))
            {
                Notify(nameof(IsChoosingAudience));
                Notify(nameof(IsWaiting));
                Notify(nameof(IsScanning));
                Notify(nameof(HasResults));

                // Installing an update closes the window, so it must not be offered while a
                // scan is running: the report being built would go with it.
                Update.ApplicationBusy = value == AppState.Scanning;

                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsWaiting => State == AppState.Waiting;

    public bool IsScanning => State == AppState.Scanning;

    public bool HasResults => State == AppState.Results;

    public bool IsDragging
    {
        get => _isDragging;
        set => Set(ref _isDragging, value);
    }

    /// <summary>True while the window is minimised, for themes that animate.</summary>
    /// <remarks>
    /// Nothing in the report depends on this. It exists so a theme with a looping background
    /// can stop the loop while there is nothing on screen to look at, which is the difference
    /// between an idle application costing nothing and costing a frame every 50 milliseconds
    /// for as long as it is left open.
    /// </remarks>
    public bool IsMinimised
    {
        get => _isMinimised;
        set => Set(ref _isMinimised, value);
    }

    /// <summary>
    /// What went wrong, in words the reader can act on or repeat to somebody who can.
    /// </summary>
    /// <remarks>
    /// Scrubbed on the way in, because most of what reaches here is an exception message from
    /// somewhere else, and the reader is being shown it precisely so they can copy it into a
    /// bug report. See <see cref="Redaction.Scrub"/>.
    /// </remarks>
    public string? Error
    {
        get => _error;
        private set => Set(ref _error, value is null ? null : Redaction.Scrub(value));
    }

    // ---- Progress ----------------------------------------------------------

    public string ProgressMessage
    {
        get => _progressMessage;
        private set => Set(ref _progressMessage, value);
    }

    public int ProgressPercent
    {
        get => _progressPercent;
        private set => Set(ref _progressPercent, value);
    }

    // ---- Results -----------------------------------------------------------

    public ScanReport? Report
    {
        get => _report;
        private set
        {
            if (Set(ref _report, value))
            {
                foreach (var name in new[]
                         {
                             nameof(ArtifactName), nameof(KindLabel), nameof(ScoreDisplay),
                             nameof(BandLabel), nameof(Band), nameof(HasMeaningfulScore),
                             nameof(AdviseAgainstInstall), nameof(BlockingReasons),
                             nameof(CoveragePercent), nameof(CoverageBasis), nameof(CoverageIsLow),
                             nameof(SummaryLine), nameof(VulnerabilitySummary), nameof(Sha256),
                             nameof(DependencyCaveat), nameof(MinificationCaveat),
                             nameof(DurationLabel), nameof(ScoreCaption),
                             nameof(AwaitingAnswer), nameof(ShowInstallBanner),
                             nameof(AccountedForReasons), nameof(HasAccountedFor),
                         })
                {
                    Notify(name);
                }

                RebuildCollections();
            }
        }
    }

    /// <summary>
    /// The result with nothing accounted for, kept so an answer can be changed or taken back.
    /// </summary>
    /// <remarks>
    /// Every displayed report is derived from this one. Deriving rather than mutating means a
    /// reader who answers wrongly is never stuck with a friendlier result than the evidence
    /// supports, and the questions themselves stay stable instead of disappearing as they are
    /// answered.
    /// </remarks>
    private ScanReport? _strict;

    private readonly HashSet<Capability> _accounted = [];
    private readonly HashSet<Capability> _answered = [];

    /// <summary>
    /// What the scanner cannot decide on its own, put to the reader rather than guessed.
    /// </summary>
    /// <remarks>
    /// Reading a browser's cookie database is a cleaner doing its job and a password stealer
    /// doing its job, and no amount of static analysis separates them. The alternative designs
    /// were both worse: guessing produces the wrong banner on honest software, and showing the
    /// red banner first and retracting it once answered teaches people that alarming banners
    /// get withdrawn.
    /// </remarks>
    public ObservableCollection<PurposeQuestion> Questions { get; } = [];

    /// <summary>
    /// Whether the verdict is being held back pending an answer.
    /// </summary>
    /// <remarks>
    /// False the moment anything fired that an answer could not change, because then the advice
    /// is settled and asking would imply otherwise. Also false once every question has been
    /// answered, whichever way.
    /// </remarks>
    public bool AwaitingAnswer =>
        Questions.Count > 0 && Report is not null && !Report.HasUnanswerableBlocking;

    /// <summary>
    /// Held back rather than shown, so the reader is never told not to install something and
    /// then told it was fine after all.
    /// </summary>
    public bool ShowInstallBanner => AdviseAgainstInstall && !AwaitingAnswer;

    public ObservableCollection<FindingCard> Findings { get; } = [];

    /// <summary>
    /// What the application can do, which is a different question from what is wrong with it.
    /// </summary>
    /// <remarks>
    /// Kept out of <see cref="Findings"/> so nothing here can be counted, coloured by severity,
    /// or read as an accusation. See <see cref="Finding.IsCapability"/>.
    /// </remarks>
    public ObservableCollection<FindingCard> Capabilities { get; } = [];

    public ObservableCollection<CategoryScore> CategoryScores { get; } = [];

    public ObservableCollection<string> Limitations { get; } = [];

    /// <summary>
    /// What the scan did. Shown beside what it could not do, so a result that arrives in under
    /// two seconds reads as quick rather than as skipped.
    /// </summary>
    public ObservableCollection<string> Effort { get; } = [];

    public string ArtifactName => Report?.ArtifactName ?? string.Empty;

    public string KindLabel => Report?.KindLabel ?? string.Empty;

    public string Sha256 => Report?.Sha256 ?? string.Empty;

    public string DurationLabel => Report is null ? string.Empty : $"{Report.Duration.TotalSeconds:F1}s";

    public string ScoreDisplay => Report?.Verdict.ScoreDisplay ?? string.Empty;

    public string BandLabel => Report?.Verdict.BandLabel ?? string.Empty;

    /// <summary>
    /// What the number is. Shown under it without exception: it is the worse of the two
    /// readings rather than an answer to whichever question this reader happens to be asking,
    /// and a number that does not say what it is invites being read as the other one.
    /// </summary>
    public string ScoreCaption => Report?.Verdict.ScoreCaption ?? Verdict.SharedScoreCaption;

    public ScoreBand Band => Report?.Verdict.Band ?? ScoreBand.InsufficientCoverage;

    public bool HasMeaningfulScore => Report?.Verdict.HasMeaningfulScore ?? false;

    public bool AdviseAgainstInstall => Report?.Verdict.AdviseAgainstInstall ?? false;

    public string BlockingReasons => Report is null
        ? string.Empty
        : string.Join("\n", Report.Verdict.BlockingReasons.Select(r => "• " + r));

    /// <summary>
    /// What the reader accounted for, shown where the banner would have been.
    /// </summary>
    /// <remarks>
    /// A result that went quiet because somebody vouched for the application has to say so on
    /// the same screen as the number. Otherwise the only difference between "nothing was found"
    /// and "something was found and waved through" is a section further down.
    /// </remarks>
    public string AccountedForReasons => Report is null
        ? string.Empty
        : string.Join("\n", Report.Verdict.AccountedFor.Select(r => "• " + r));

    public bool HasAccountedFor => Report?.Verdict.AccountedFor.Count > 0;

    public int CoveragePercent => Report?.Coverage.Percent ?? 0;

    public string CoverageBasis => Report?.Coverage.Basis ?? string.Empty;

    /// <summary>Drives the caveat shown under the coverage meter.</summary>
    public bool CoverageIsLow => Report is not null && Report.Coverage.Percent < 50;

    /// <summary>Phrased in the report itself, so this window and the export cannot disagree.</summary>
    public string SummaryLine => Report?.SummaryLine ?? string.Empty;

    /// <summary>
    /// Shown beside the score when a class of check could not run. Null hides the panel, which
    /// is why it is bound rather than being made an empty string.
    /// </summary>
    public string? DependencyCaveat => Report?.DependencyCaveat;

    /// <summary>
    /// Shown beside the score when most of the application ships as a bundle. Bound the same
    /// way as the caveat above, and null for the same reason.
    /// </summary>
    public string? MinificationCaveat => Report?.MinificationCaveat;

    public string VulnerabilitySummary => Report is null
        ? string.Empty
        : Report.VulnerabilityData.Describe(Report.ScannedAt);

    // ---- Commands ----------------------------------------------------------

    public ICommand ScanCommand { get; }

    public ICommand CancelCommand { get; }

    public ICommand ResetCommand { get; }

    public ICommand ExportMarkdownCommand { get; }

    public ICommand ExportJsonCommand { get; }

    /// <summary>Runs a scan. Called from the drop handler and the browse button.</summary>
    public async Task ScanAsync(string path)
    {
        if (State == AppState.Scanning)
        {
            return;
        }

        Error = null;
        Report = null;
        ProgressPercent = 0;
        ProgressMessage = "Starting";
        State = AppState.Scanning;

        _cancellation = new CancellationTokenSource();

        // Read once rather than per property: three settings have to describe the same source,
        // and a half-filled ScanOptions is answered by whichever branch the runner reaches
        // first. An endpoint left in beside a key would win over it there.
        var endpoint = DeepPassEnabled && DeepPassUsesEndpoint ? _endpoint : null;

        var options = new ScanOptions
        {
            Audience = Audience,

            // Only when the reader switched the pass on for this scan and chose a source that
            // can answer.
            DeepPassApiKey = DeepPassEnabled && DeepPassUsesApiKey ? ApiKeyStore.Load() : null,
            DeepPassUseLocalCli = DeepPassEnabled && DeepPassUsesLocalCli,
            DeepPassEndpoint = endpoint?.Endpoint,
            DeepPassEndpointKey = endpoint?.Key,

            // The model belongs to the endpoint and only to the endpoint. Left set for another
            // source it would override the Claude model that route was built around.
            DeepPassModel = endpoint?.Model,
        };

        try
        {
            // Measured before the clock starts, because how long the readout runs depends on
            // how much there was to look at. Off the UI thread: a large source tree is a lot
            // of directory entries.
            var bytes = await Task.Run(() => ScanPacing.Measure(path), _cancellation.Token);

            var pacer = new ScanPacer(ScanPacing.TargetFor(bytes));

            // Constructed here rather than inside the scan, so its callbacks come back to this
            // thread and the pacer is only ever touched from one place.
            var progress = new Progress<ScanProgress>(pacer.Record);

            var clock = Stopwatch.StartNew();

            // The rule pass is CPU-bound and parallel, so it must not run on the UI thread.
            var scan = Task.Run(
                () => _scanner.ScanAsync(path, options, progress, _cancellation.Token),
                _cancellation.Token);

            await ShowProgressAsync(pacer, clock, scan);

            var report = await scan;

            ProgressPercent = 100;

            _strict = report;
            _accounted.Clear();
            _answered.Clear();

            Report = report;
            RebuildQuestions();

            State = AppState.Results;
        }
        catch (OperationCanceledException)
        {
            State = AppState.Waiting;
        }
        catch (Exception ex)
        {
            Error = $"{ex.GetType().Name}: {ex.Message}";
            State = AppState.Waiting;
        }
        finally
        {
            _cancellation?.Dispose();
            _cancellation = null;
        }
    }

    /// <summary>How often the readout is redrawn while a scan runs.</summary>
    private static readonly TimeSpan Tick = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// Drives the progress readout until both the scan has finished and it has had its time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns the moment the scan fails or is cancelled, without waiting out the rest of the
    /// pacing. Somebody who has pressed Cancel, or handed over a file that cannot be read, is
    /// owed the answer now; making them watch a bar fill up first would be the point at which
    /// pacing turned into wasting their time.
    /// </para>
    /// <para>
    /// The bar cannot run ahead of the work regardless of what happens here. See
    /// <see cref="ScanPacer"/>, which caps what it reports by what the scanner has said.
    /// </para>
    /// </remarks>
    private async Task ShowProgressAsync(ScanPacer pacer, Stopwatch clock, Task scan)
    {
        while (true)
        {
            var sample = pacer.Sample(clock.Elapsed);

            ProgressPercent = sample.Percent;

            if (sample.Message.Length > 0)
            {
                ProgressMessage = sample.Message;
            }

            if (scan.IsFaulted || scan.IsCanceled)
            {
                return;
            }

            if (scan.IsCompleted && pacer.Finished(clock.Elapsed))
            {
                return;
            }

            await Task.Delay(Tick, _cancellation?.Token ?? CancellationToken.None);
        }
    }

    private void Reset()
    {
        Report = null;
        Error = null;

        // Answers belong to the artifact they were given about. Carrying them into the next
        // scan would account for behaviour in one application on the strength of what somebody
        // said about a different one.
        _strict = null;
        _accounted.Clear();
        _answered.Clear();
        RebuildQuestions();

        State = AppState.Waiting;
    }

    /// <summary>
    /// Whether the list contains anything the deep pass inferred, which decides whether the
    /// note above it is shown. Stated once there rather than on every card.
    /// </summary>
    public bool HasAssistedFindings => Findings.Any(f => f.IsAssisted);

    /// <summary>
    /// Every check and what became of it, in the order a reader wants them: what fired, then
    /// what passed, then what never ran.
    /// </summary>
    public ObservableCollection<CheckCard> Checks { get; } = [];

    /// <summary>The three counts in one line, since any two without the third mislead.</summary>
    public string ChecksSummary => Report?.Checks.Describe() ?? string.Empty;

    // ---- What each section is holding --------------------------------------

    /// <summary>
    /// The counts shown beside the headings on the results screen, one per section that can be
    /// folded away.
    /// </summary>
    /// <remarks>
    /// A section may be closed but not silent about its own size. Without these, folding "what
    /// could not be checked" away leaves a screen identical to a scan that had nothing it could
    /// not check.
    /// </remarks>
    public string FindingsCount => Counted(Findings.Count, "finding");

    public string ChecksCount => Counted(Checks.Count, "check");

    public string CapabilitiesCount => Counted(Capabilities.Count, "capability", "capabilities");

    public string CategoriesCount => Counted(CategoryScores.Count, "category", "categories");

    /// <summary>
    /// Deliberately "notes" rather than "checks": the list holds both checks that could not run
    /// and remarks about how the scan was answered, and counting the second kind as the first
    /// would overstate what was missed.
    /// </summary>
    public string LimitationsCount => Counted(Limitations.Count, "note");

    public string CoverageCount => Report is null ? string.Empty : $"{CoveragePercent}% readable";

    private static string Counted(int count, string one, string? many = null) =>
        count == 1 ? $"1 {one}" : $"{count} {many ?? one + "s"}";

    /// <summary>
    /// How the score was arrived at, shown under it. A low number with no account of itself
    /// reads as a judgement rather than a measurement.
    /// </summary>
    public ObservableCollection<string> ScoreExplanation { get; } = [];

    /// <summary>
    /// Puts the questions the scan could not answer to the reader.
    /// </summary>
    /// <remarks>
    /// Taken from the strict result rather than the displayed one, so answering does not make
    /// the question vanish from the list. A reader who says yes and then reconsiders can say no
    /// again without rescanning.
    /// </remarks>
    private void RebuildQuestions()
    {
        Questions.Clear();

        if (_strict is not null)
        {
            foreach (var capability in Scanner.QuestionsFor(_strict).Except(_answered))
            {
                Questions.Add(new PurposeQuestion(capability, Answer));
            }
        }

        Notify(nameof(AwaitingAnswer));
        Notify(nameof(ShowInstallBanner));
    }

    /// <summary>
    /// Records one answer and re-reads the report against it, without rescanning.
    /// </summary>
    /// <remarks>
    /// Declining is recorded as an answer rather than ignored, because a question left on
    /// screen forever would hold the verdict back indefinitely. Saying no resolves it to
    /// exactly the reading the scan produced on its own.
    /// </remarks>
    private void Answer(Capability capability, bool hasReason)
    {
        _answered.Add(capability);

        if (hasReason)
        {
            _accounted.Add(capability);
        }
        else
        {
            _accounted.Remove(capability);
        }

        if (_strict is not null)
        {
            Report = Scanner.Reconsider(
                _strict,
                _accounted.Count == 0 ? null : DeclaredPurpose.FromReader([.. _accounted]));
        }

        RebuildQuestions();
    }

    private void RebuildCollections()
    {
        Findings.Clear();
        Capabilities.Clear();
        CategoryScores.Clear();
        Limitations.Clear();
        Effort.Clear();
        Checks.Clear();
        ScoreExplanation.Clear();

        if (Report is null)
        {
            Notify(nameof(HasAssistedFindings));
            Notify(nameof(ChecksSummary));
            NotifySectionCounts();
            return;
        }

        if (Report.Verdict.HasMeaningfulScore && Report.Verdict.Explanation is { } explanation)
        {
            foreach (var line in explanation.Describe())
            {
                ScoreExplanation.Add(line);
            }
        }

        // Fired first, then passed, then never ran. A reader opening this wants the problems,
        // but the passes are the reason the section exists: a list of failures alone says
        // nothing about how much was examined and found sound.
        foreach (var check in Report.Checks.Checks
                     .OrderBy(c => c.State switch
                     {
                         CheckState.FoundIssues => 0,
                         CheckState.Passed => 1,
                         _ => 2,
                     })
                     .ThenBy(c => c.Id, StringComparer.Ordinal))
        {
            Checks.Add(new CheckCard(check, Audience));
        }

        Notify(nameof(ChecksSummary));

        foreach (var line in Report.Effort.Describe(Report.ScannedAt))
        {
            Effort.Add(line);
        }

        foreach (var finding in Report.FindingsBySeverity)
        {
            Findings.Add(new FindingCard(finding, Audience));
        }

        foreach (var capability in Report.Capabilities)
        {
            Capabilities.Add(new FindingCard(capability, Audience));
        }

        Notify(nameof(HasAssistedFindings));

        foreach (var (category, score) in Report.CategoryScores
                     .Where(kv => kv.Value < 100)
                     .OrderBy(kv => kv.Value))
        {
            CategoryScores.Add(new CategoryScore(Humanise(category), score));
        }

        foreach (var limitation in Report.Coverage.ChecksNotPossible)
        {
            Limitations.Add(limitation);
        }

        NotifySectionCounts();
    }

    /// <summary>
    /// Raised by hand because every one of these reads a collection's Count. An
    /// ObservableCollection tells a binding that its items changed, not that a string property
    /// derived from its length did.
    /// </summary>
    private void NotifySectionCounts()
    {
        foreach (var name in new[]
                 {
                     nameof(FindingsCount), nameof(ChecksCount), nameof(CategoriesCount),
                     nameof(LimitationsCount), nameof(CoverageCount), nameof(CapabilitiesCount),
                 })
        {
            Notify(name);
        }
    }

    private void Export(string format)
    {
        if (Report is null)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"{Report.ArtifactName}-vibecheck.{format}",
            Filter = format == "md"
                ? "Markdown (*.md)|*.md"
                : "JSON (*.json)|*.json",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, format == "md"
                ? MarkdownReportWriter.Write(Report)
                : JsonReportWriter.Write(Report));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Error = $"Could not write the report: {ex.Message}";
        }
    }

    private static string Humanise(FindingCategory category) => category.Humanise();

    // ---- INotifyPropertyChanged --------------------------------------------

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        Notify(name);

        return true;
    }

    private void Notify(string? name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// One finding as shown to a particular reader.
/// </summary>
/// <remarks>
/// The audience is resolved here rather than in the view, so no binding can reach past it to
/// the developer's copy.
/// </remarks>
/// <summary>
/// One thing the scan observed but cannot judge, put to the reader.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a question about a specific behaviour rather than a menu of kinds of
/// application. Naming kinds fails twice: the list has no end, and picking a flattering label
/// off it is easy and deniable. Affirming that <i>this application has a reason to read browser
/// cookies</i> is a specific claim, and the report prints it back in those words, so a
/// screenshot of a quiet result still shows what bought the quiet.
/// </para>
/// <para>
/// Both answers are offered plainly and neither is preselected. A default here would be the
/// scanner guessing, which is the thing it is asking because it cannot do.
/// </para>
/// </remarks>
public sealed class PurposeQuestion
{
    public PurposeQuestion(Capability capability, Action<Capability, bool> answer)
    {
        ArgumentNullException.ThrowIfNull(answer);

        Capability = capability;
        HasReasonCommand = new RelayCommand(_ => answer(capability, true));
        NoReasonCommand = new RelayCommand(_ => answer(capability, false));
    }

    public Capability Capability { get; }

    /// <summary>What was observed, in the reader's terms rather than the rule's.</summary>
    public string Statement
    {
        get
        {
            var phrase = Capability.Humanise();

            return $"This application can {char.ToLowerInvariant(phrase[0])}{phrase[1..]}.";
        }
    }

    /// <summary>
    /// Who legitimately does this, so the answer is an informed one rather than a guess.
    /// </summary>
    /// <remarks>
    /// The second sentence matters as much as the first. Without it a reader has no basis to
    /// answer and will tend to say yes, which would make the question a formality.
    /// </remarks>
    public string Context =>
        $"Expected of {Capability.ExpectedOf()}. Unusual in anything else, and this alone "
        + "would otherwise advise against installing it.";

    public string Prompt => "Does it have a reason to?";

    public ICommand HasReasonCommand { get; }

    public ICommand NoReasonCommand { get; }
}

public sealed class FindingCard(Finding finding, Audience audience) : INotifyPropertyChanged
{
    private bool _expanded;

    public Finding Finding { get; } = finding;

    public string Title => Finding.Title;

    public Severity Severity => Finding.SeverityFor(audience);

    /// <summary>
    /// "INFO" is accurate and unhelpful. For the reader a finding does not reach, the useful
    /// label is the reason it is sitting at the bottom of their list.
    /// </summary>
    public string SeverityLabel =>
        Severity == Severity.Info && audience == Audience.EndUser
            ? "NOT YOURS"
            : Severity.ToString().ToUpperInvariant();

    public string Location => Finding.Location;

    public string RuleId => Finding.RuleId;

    /// <summary>
    /// The rule identifier is a support handle for someone who can act on it. Hidden from the
    /// reader who cannot, where it is a serial number attached to their own anxiety.
    /// </summary>
    public bool ShowRuleId => audience == Audience.Developer || IsAssisted;

    /// <summary>
    /// What produced this, in the slot the rule identifier occupies.
    /// </summary>
    /// <remarks>
    /// A two-letter tag rather than a sentence. Where a finding came from is worth knowing at
    /// a glance, and the banner it replaces said the same thing at forty times the length on
    /// every card until it read as the tool disowning its own output.
    /// </remarks>
    public string SourceTag => IsAssisted ? "AI" : Finding.RuleId;

    /// <summary>
    /// What the identifier means, on hover.
    /// </summary>
    /// <remarks>
    /// A code like VC-MAL-003 asks the reader to take the filing system on trust. It is worth
    /// showing, being the thing to quote in a bug report, but only once it can be read. The
    /// deep pass tag is described by its own family rather than by the rule it did not come
    /// from.
    /// </remarks>
    public string FamilyTooltip => RuleFamily.Tooltip(IsAssisted ? "VC-AI-001" : Finding.RuleId);

    public string Description => Finding.DescriptionFor(audience);

    public string? Evidence => Finding.Evidence;

    public string? Remediation => Finding.RemediationFor(audience);

    /// <summary>"How to fix" is wrong for somebody who cannot fix it.</summary>
    public string RemediationLabel =>
        audience == Audience.EndUser ? "What you can do" : "How to fix";

    /// <summary>
    /// A CVE link is the most useful thing in the developer's copy and a dead end in the
    /// other: it opens an advisory about a component the reader cannot upgrade.
    /// </summary>
    public string? Reference => audience == Audience.Developer ? Finding.Reference : null;

    /// <summary>Shown on inferred findings so they are never mistaken for a certain match.</summary>
    public bool IsAssisted => Finding.Source == FindingSource.Assisted;

    public bool Expanded
    {
        get => _expanded;
        set
        {
            if (_expanded == value)
            {
                return;
            }

            _expanded = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Expanded)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed record CategoryScore(string Name, int Score);

/// <summary>
/// One check as the results screen shows it.
/// </summary>
/// <remarks>
/// A tick and a dash must read as different things at a glance: a check that passed and a check
/// that had nothing to run against are opposite results.
/// </remarks>
public sealed class CheckCard(CheckOutcome check, Audience audience)
{
    public string Title => check.Title;

    /// <summary>Hidden from the reader who cannot act on it, as in the findings list.</summary>
    public string Id => audience == Audience.Developer ? check.Id : string.Empty;

    public bool ShowId => audience == Audience.Developer;

    /// <summary>What this check's family covers, on hover, as in the findings list.</summary>
    public string FamilyTooltip => RuleFamily.Tooltip(check.Id);

    public bool Passed => check.State == CheckState.Passed;

    public bool FoundIssues => check.State == CheckState.FoundIssues;

    public bool NotChecked => check.State == CheckState.NotChecked;

    /// <summary>
    /// What the outcome is worth. A pass over four hundred files and a pass over one are not
    /// the same reassurance, so the count travels with the tick rather than being implied.
    /// </summary>
    public string Detail => check.State == CheckState.NotChecked
        ? "nothing it applies to was found"
        : $"{check.FilesExamined:N0} file{(check.FilesExamined == 1 ? "" : "s")} examined";
}

/// <summary>Minimal command implementation; the app has a handful of actions.</summary>
public sealed class RelayCommand(Action<object?> execute, Predicate<object?>? canExecute = null) : ICommand
{
    public bool CanExecute(object? parameter) => canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => execute(parameter);

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
