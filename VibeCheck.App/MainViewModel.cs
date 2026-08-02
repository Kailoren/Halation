using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;

using VibeCheck.Core;
using VibeCheck.Core.DeepPass;
using VibeCheck.Core.Dependencies;
using VibeCheck.Core.Model;
using VibeCheck.Core.Reporting;

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

            if (DeepPassUsesLocalCli && !LocalCliReady)
            {
                DeepPassUsesLocalCli = false;
            }

            if (_deepPassEnabled && !DeepPassSourceReady)
            {
                _deepPassEnabled = false;
                Notify(nameof(DeepPassEnabled));
                Notify(nameof(PrivacyLine));
            }

            // The score is a different number for the other reader, not the same number
            // relabelled, so everything downstream of it has to be rebuilt.
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
    private bool _deepPassUsesLocalCli;
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
            if (value && !DeepPassSourceReady)
            {
                if (LocalCliReady)
                {
                    DeepPassUsesLocalCli = true;
                }
                else if (HasApiKey)
                {
                    DeepPassUsesLocalCli = false;
                }
            }

            // Still nothing available. Untick rather than claim a pass that will not happen.
            if (value && !DeepPassSourceReady)
            {
                Set(ref _deepPassEnabled, false);
                Notify(nameof(DeepPassEnabled));
            }

            Notify(nameof(PrivacyLine));
            Notify(nameof(CanChooseApiKey));
            Notify(nameof(CanChooseLocalCli));
        }
    }

    /// <summary>
    /// Whether the source choice is live.
    /// </summary>
    /// <remarks>
    /// The checkbox is the switch and these are the settings behind it, which is the only
    /// arrangement where the checkbox earns its place. Storing an API key stays reachable
    /// whether or not the pass is on, because it is configuration rather than part of this
    /// scan's choice, and gating it behind the switch would leave someone with no key unable
    /// to reach the control that would give them one.
    /// </remarks>
    public bool CanChooseApiKey => DeepPassEnabled && HasApiKey;

    public bool CanChooseLocalCli => DeepPassEnabled && LocalCliReady;

    /// <summary>
    /// Whether the pass runs through a Claude Code installation on this machine rather than a
    /// key the reader bought.
    /// </summary>
    /// <remarks>
    /// Two radio buttons bind to this and its inverse. Changing it can invalidate the pass
    /// itself, because each source has its own reasons for being unavailable.
    /// </remarks>
    public bool DeepPassUsesLocalCli
    {
        get => _deepPassUsesLocalCli;
        set
        {
            if (!Set(ref _deepPassUsesLocalCli, value))
            {
                return;
            }

            Notify(nameof(DeepPassUsesApiKey));
            Notify(nameof(PrivacyLine));
            Notify(nameof(DeepPassCostLine));

            if (_deepPassEnabled && !DeepPassSourceReady)
            {
                _deepPassEnabled = false;
                Notify(nameof(DeepPassEnabled));
                Notify(nameof(PrivacyLine));
            }
        }
    }

    public bool DeepPassUsesApiKey
    {
        get => !_deepPassUsesLocalCli;
        set
        {
            if (value)
            {
                DeepPassUsesLocalCli = false;
            }
        }
    }

    public bool HasApiKey => ApiKeyStore.Load() is not null;

    /// <summary>
    /// Whether the deep pass is offered to this reader at all.
    /// </summary>
    /// <remarks>
    /// Developer view only. Not a security rule (the API endpoint cannot execute anything, so
    /// the key route would be safe on untrusted code) but a product one: someone checking
    /// software they downloaded is asking whether to trust it, and an answer that costs money
    /// and requires an Anthropic account is not the answer that question wants. The core still
    /// permits an API-backed pass for either audience, so a library caller is not bound by
    /// this; it is a decision about what this window offers.
    /// </remarks>
    public bool DeepPassOfferedHere => Audience == Audience.Developer;

    /// <summary>Whether the source currently chosen can actually answer.</summary>
    public bool DeepPassSourceReady =>
        DeepPassOfferedHere && (DeepPassUsesLocalCli ? LocalCliReady : HasApiKey);

    /// <summary>Whether anything at all could answer, which is what gates the checkbox.</summary>
    public bool CanRunDeepPass => DeepPassOfferedHere && (HasApiKey || LocalCliReady);

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
    /// The audience is part of the test, not a presentational detail. Claude Code can act on
    /// this machine and the Anthropic API cannot, so feeding it source recovered from software
    /// the reader did not write is the attack this tool exists to warn about. The core refuses
    /// regardless; this only decides whether the option is offered rather than explained.
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
    /// <para>
    /// The credential never passes through this application and is not supposed to. Claude Code
    /// opens its own browser flow, the reader authenticates with Anthropic directly, and the
    /// result lands in the CLI's own store. VibeCheck learns only what <c>auth status</c> tells
    /// it afterwards, which is a yes or a no.
    /// </para>
    /// <para>
    /// The arguments are a fixed literal and nothing the reader typed reaches the command line.
    /// The only variable is the executable path, and that came from the locator's own search
    /// rather than from input. <c>UseShellExecute</c> is on because this is the one place the
    /// process is meant to be seen: it is an interactive sign-in and it needs a console of its
    /// own to run in.
    /// </para>
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
    public string DeepPassCostLine => DeepPassUsesLocalCli
        ? "Spends your Claude subscription's quota. Nothing is charged to you."
        : "Billed to your Anthropic API key, per file read.";

    /// <summary>
    /// The standing promise on the drop screen, which stops being true the moment the deep
    /// pass is switched on. Leaving "nothing is uploaded" showing while source is about to be
    /// sent to an API would be the plainest possible lie this interface could tell.
    /// </summary>
    /// <remarks>
    /// Both routes send code to Anthropic. Only the billing differs, so the local option must
    /// not be allowed to read as the private one.
    /// </remarks>
    public string PrivacyLine => (DeepPassEnabled, DeepPassUsesLocalCli) switch
    {
        (false, _) => "Nothing is uploaded. Analysis runs on this machine.",

        (true, true) => "Deep pass is on: the files it selects will be sent to Anthropic through "
                        + "Claude Code, on your subscription. Everything else runs on this machine.",

        (true, false) => "Deep pass is on: the files it selects will be sent to Anthropic on your "
                         + "key. Everything else runs on this machine.",
    };

    public string ApiKeyStatus => ApiKeyStore.Describe(ApiKeyStore.Load());

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
        Notify(nameof(CanChooseApiKey));
        Notify(nameof(DeepPassEnabled));
        Notify(nameof(PrivacyLine));
    }

    /// <summary>
    /// Looks for a usable Claude Code installation, off the UI thread.
    /// </summary>
    /// <remarks>
    /// Installed and signed in are separate facts, and the second costs a process launch to
    /// establish, so it is done once at startup rather than when the scan button is pressed.
    /// Finding nothing is a normal outcome and is reported in the status line, never as an
    /// error: most readers will not have Claude Code, and that is not a problem with their
    /// machine.
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

    public string? Error
    {
        get => _error;
        private set => Set(ref _error, value);
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
                             nameof(SummaryLine), nameof(VulnerabilitySummary),
                             nameof(VulnerabilityIsStale), nameof(Sha256),
                             nameof(DurationLabel), nameof(ScoreCaption),
                         })
                {
                    Notify(name);
                }

                RebuildCollections();
            }
        }
    }

    public ObservableCollection<FindingCard> Findings { get; } = [];

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
    /// Which question the score answered. Shown under the number without exception: the same
    /// artifact scores differently for the two readers, and a number that changes with a
    /// setting and does not say so is worse than either number alone.
    /// </summary>
    public string ScoreCaption => Report?.Verdict.ScoreCaption ?? Audience.ScoreCaption();

    public ScoreBand Band => Report?.Verdict.Band ?? ScoreBand.InsufficientCoverage;

    public bool HasMeaningfulScore => Report?.Verdict.HasMeaningfulScore ?? false;

    public bool AdviseAgainstInstall => Report?.Verdict.AdviseAgainstInstall ?? false;

    public string BlockingReasons => Report is null
        ? string.Empty
        : string.Join("\n", Report.Verdict.BlockingReasons.Select(r => "• " + r));

    public int CoveragePercent => Report?.Coverage.Percent ?? 0;

    public string CoverageBasis => Report?.Coverage.Basis ?? string.Empty;

    /// <summary>Drives the caveat shown under the coverage meter.</summary>
    public bool CoverageIsLow => Report is not null && Report.Coverage.Percent < 50;

    public string SummaryLine
    {
        get
        {
            if (Report is null)
            {
                return string.Empty;
            }

            var counts = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }
                .Select(s => (Severity: s, Count: Report.CountOf(s)))
                .Where(x => x.Count > 0)
                .Select(x => $"{x.Count} {x.Severity.ToString().ToLowerInvariant()}")
                .ToList();

            return counts.Count == 0
                ? "No issues were found by the checks that ran."
                : $"Found {string.Join(", ", counts)}.";
        }
    }

    public string VulnerabilitySummary => Report is null
        ? string.Empty
        : Report.VulnerabilityData.Describe(Report.ScannedAt);

    public bool VulnerabilityIsStale =>
        Report is not null && Report.VulnerabilityData.IsStale(Report.ScannedAt);

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

        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressMessage = p.Message;
            ProgressPercent = p.Percent ?? ProgressPercent;
        });

        var options = new ScanOptions
        {
            Audience = Audience,

            // Only when the reader switched the pass on for this scan and chose a source that
            // can answer.
            DeepPassApiKey = DeepPassEnabled && !DeepPassUsesLocalCli ? ApiKeyStore.Load() : null,
            DeepPassUseLocalCli = DeepPassEnabled && DeepPassUsesLocalCli,
        };

        try
        {
            // The rule pass is CPU-bound and parallel, so it must not run on the UI thread.
            var report = await Task.Run(
                () => _scanner.ScanAsync(path, options, progress, _cancellation.Token),
                _cancellation.Token);

            Report = report;
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

    private void Reset()
    {
        Report = null;
        Error = null;
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

    /// <summary>
    /// How the score was arrived at, shown under it. A low number with no account of itself
    /// reads as a judgement rather than a measurement.
    /// </summary>
    public ObservableCollection<string> ScoreExplanation { get; } = [];

    private void RebuildCollections()
    {
        Findings.Clear();
        CategoryScores.Clear();
        Limitations.Clear();
        Effort.Clear();
        Checks.Clear();
        ScoreExplanation.Clear();

        if (Report is null)
        {
            Notify(nameof(HasAssistedFindings));
            Notify(nameof(ChecksSummary));
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

/// <summary>One finding, prepared for display.</summary>
/// <summary>
/// One finding as shown to a particular reader.
/// </summary>
/// <remarks>
/// The audience is resolved here rather than in the view, so no binding can accidentally
/// reach past it to the developer's copy. Every member below that differs between the two
/// readers goes through the finding's own accessor.
/// </remarks>
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
/// The three states are rendered distinctly on purpose. A tick and a dash have to be legible
/// as different things at a glance, because a check that passed and a check that had nothing
/// to run against are opposite results, and a reader who reads them as the same has been
/// told a scan covered ground it never reached.
/// </remarks>
public sealed class CheckCard(CheckOutcome check, Audience audience)
{
    public string Title => check.Title;

    /// <summary>Hidden from the reader who cannot act on it, as in the findings list.</summary>
    public string Id => audience == Audience.Developer ? check.Id : string.Empty;

    public bool ShowId => audience == Audience.Developer;

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
