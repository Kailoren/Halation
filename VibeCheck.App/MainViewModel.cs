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
    Waiting,
    Scanning,
    Results,
}

/// <summary>Drives the whole window. Deliberately one view model; the app has three screens.</summary>
public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly Scanner _scanner = new();
    private CancellationTokenSource? _cancellation;

    private AppState _state = AppState.Waiting;
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
        }
    }

    public bool HasApiKey => ApiKeyStore.Load() is not null;

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
                             nameof(DurationLabel),
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
            Findings.Add(new FindingCard(finding));
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
public sealed class FindingCard(Finding finding) : INotifyPropertyChanged
{
    private bool _expanded;

    public Finding Finding { get; } = finding;

    public string Title => Finding.Title;

    public Severity Severity => Finding.Severity;

    public string SeverityLabel => Finding.Severity.ToString().ToUpperInvariant();

    public string Location => Finding.Location;

    public string RuleId => Finding.RuleId;

    public string Description => Finding.Description;

    public string? Evidence => Finding.Evidence;

    public string? Remediation => Finding.Remediation;

    public string? Reference => Finding.Reference;

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
