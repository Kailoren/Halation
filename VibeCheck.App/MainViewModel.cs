using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;

using VibeCheck.Core;
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

    private AppState _state = AudienceStore.Load() is null
        ? AppState.ChoosingAudience
        : AppState.Waiting;

    private Audience _audience = AudienceStore.Load() ?? Audience.Developer;
    private string _progressMessage = string.Empty;
    private int _progressPercent;
    private bool _isolate;
    private bool _isDragging;
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

    /// <summary>
    /// Whether this scan runs the optional deep pass. Off by default and not remembered
    /// between runs: it spends the reader's own money, so it should be a decision each time
    /// rather than a setting that quietly stays on.
    /// </summary>
    public bool DeepPassEnabled
    {
        get => _deepPassEnabled;
        set
        {
            if (Set(ref _deepPassEnabled, value) && value && !HasApiKey)
            {
                // Nothing to run with. Turn it back off rather than letting the checkbox
                // claim a pass that will not happen.
                Set(ref _deepPassEnabled, false);
                Notify(nameof(DeepPassEnabled));
            }

            Notify(nameof(PrivacyLine));
        }
    }

    public bool HasApiKey => ApiKeyStore.Load() is not null;

    /// <summary>
    /// The standing promise on the drop screen, which stops being true the moment the deep
    /// pass is switched on. Leaving "nothing is uploaded" showing while source is about to be
    /// sent to an API would be the plainest possible lie this interface could tell.
    /// </summary>
    public string PrivacyLine => DeepPassEnabled
        ? "Deep pass is on: the files it selects will be sent to Anthropic on your key. "
          + "Everything else runs on this machine."
        : "Nothing is uploaded. Analysis runs on this machine.";

    public string ApiKeyStatus => ApiKeyStore.Describe(ApiKeyStore.Load());

    /// <summary>Stores or clears the key, then refreshes everything that depends on it.</summary>
    public void SetApiKey(string? key)
    {
        ApiKeyStore.Save(key);

        if (!HasApiKey)
        {
            _deepPassEnabled = false;
        }

        Notify(nameof(HasApiKey));
        Notify(nameof(ApiKeyStatus));
        Notify(nameof(DeepPassEnabled));
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

    public string? Error
    {
        get => _error;
        private set => Set(ref _error, value);
    }

    /// <summary>
    /// When set, the scan makes no network request of any kind.
    /// </summary>
    /// <remarks>
    /// Intended for examining a sample on a machine cut off from everything, using the data
    /// bundle a previous online scan left beside it.
    /// </remarks>
    public bool Isolate
    {
        get => _isolate;
        set
        {
            if (Set(ref _isolate, value))
            {
                Notify(nameof(IsolateExplanation));
            }
        }
    }

    public string IsolateExplanation => Isolate
        ? "No network requests. Dependencies are checked only against a data bundle from an earlier scan."
        : "Dependencies are checked against current advisories. Only package names and versions are sent.";

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
                             nameof(VulnerabilityIsStale), nameof(BundleNote), nameof(Sha256),
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

    public string? BundleNote => Report?.BundlePath is { } path
        ? $"Offline data bundle written: {Path.GetFileName(path)}"
        : null;

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
            Isolate = Isolate,
            WriteBundle = !Isolate,
            Audience = Audience,

            // Only when the reader both stored a key and switched the pass on for this scan.
            // Isolate mode ignores it regardless, since that mode promises no network at all.
            DeepPassApiKey = DeepPassEnabled ? ApiKeyStore.Load() : null,
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

    private void RebuildCollections()
    {
        Findings.Clear();
        CategoryScores.Clear();
        Limitations.Clear();
        Effort.Clear();

        if (Report is null)
        {
            return;
        }

        foreach (var line in Report.Effort.Describe(Report.ScannedAt))
        {
            Effort.Add(line);
        }

        foreach (var finding in Report.FindingsBySeverity)
        {
            Findings.Add(new FindingCard(finding, Audience));
        }

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

    private static string Humanise(FindingCategory category) => category switch
    {
        FindingCategory.Secrets => "Credentials",
        FindingCategory.Dependencies => "Dependencies",
        FindingCategory.Network => "Network",
        FindingCategory.Auth => "Access control",
        FindingCategory.CodeSafety => "Code safety",
        FindingCategory.BinaryHygiene => "Binary hygiene",
        _ => category.ToString(),
    };

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
    public bool ShowRuleId => audience == Audience.Developer;

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
