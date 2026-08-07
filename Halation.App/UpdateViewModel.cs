using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;

using Halation.Core;
using Halation.Core.Update;

namespace Halation.App;

public enum UpdateStage
{
    /// <summary>Nothing has been asked, either because the check is off or it has not run yet.</summary>
    Idle,
    Checking,

    /// <summary>Asked and answered: this is the newest build published.</summary>
    Current,
    Available,
    Downloading,
    Verifying,

    /// <summary>Tried and refused, or tried and broke. The reason is in <see cref="UpdateViewModel.Detail"/>.</summary>
    Failed,
}

/// <summary>
/// Tells the reader when a newer build exists, and replaces this one with it when that can be
/// done safely.
/// </summary>
/// <remarks>
/// <para>
/// Its own view model rather than more of <see cref="MainViewModel"/>: none of this has
/// anything to do with a scan, and the states it moves through are its own.
/// </para>
/// <para>
/// Nothing here happens without being asked. The check runs at startup and says so; the
/// download happens on a button; and the install refuses outright unless the downloaded build
/// carries the signature of the publisher this one was signed by. An updater is the one part
/// of an application that decides what code runs tomorrow, so the interesting behaviour is all
/// in what it declines to do.
/// </para>
/// </remarks>
public sealed class UpdateViewModel : INotifyPropertyChanged
{
    private readonly InstallCapability _capability;
    private UpdateSettings _settings;
    private CancellationTokenSource? _cancellation;

    private UpdateStage _stage = UpdateStage.Idle;
    private AvailableUpdate? _update;
    private string _detail = string.Empty;
    private double _progress;
    private bool _dismissed;
    private bool _applicationBusy;

    public UpdateViewModel()
    {
        _settings = UpdateSettingsStore.Load();
        _capability = UpdateInstall.Assess(Environment.ProcessPath);

        InstallCommand = new RelayCommand(_ => _ = InstallAsync(), _ => CanStartInstall);
        OpenReleasePageCommand = new RelayCommand(_ => OpenReleasePage());
        DismissCommand = new RelayCommand(_ => Dismiss());
        CancelCommand = new RelayCommand(_ => _cancellation?.Cancel(), _ => IsWorking);

        // Whatever the last update left behind, now that the build it replaced is not running.
        UpdateInstall.SweepSuperseded(Environment.ProcessPath);

        // A packaged copy never asks. The Store both distributes and updates it, so a check
        // here could only announce a download the application must not install: replacing your
        // own binary outside the Store is against Store policy, which makes an update strip
        // pointing at GitHub a certification risk rather than a helpful notice.
        if (_settings.CheckOnStartup && !PackageIdentity.IsPackaged)
        {
            _ = CheckAsync();
        }
    }

    /// <summary>
    /// Whether the update section is worth showing at all.
    /// </summary>
    /// <remarks>
    /// False for a packaged copy, where every control in it is either inert or forbidden. An
    /// always-disabled panel explaining that updates happen elsewhere is worse than no panel:
    /// it puts a dead control in front of the reader on every launch.
    /// </remarks>
    public bool IsSelfUpdating => !PackageIdentity.IsPackaged;

    // ---- What the reader has decided ---------------------------------------

    /// <summary>
    /// Whether VibeCheck asks GitHub what has been published when it starts.
    /// </summary>
    /// <remarks>
    /// Switchable because the application's standing promise is that it says what leaves the
    /// machine. Nothing is sent but the request itself: which version is running is compared
    /// here, not there.
    /// </remarks>
    public bool CheckOnStartup
    {
        get => _settings.CheckOnStartup;
        set
        {
            if (_settings.CheckOnStartup == value)
            {
                return;
            }

            _settings = _settings with { CheckOnStartup = value };
            UpdateSettingsStore.Save(_settings);
            Notify(nameof(CheckOnStartup));

            // Turned on mid-session, so answer the question it was turned on to ask rather
            // than waiting for the next launch.
            if (value && !PackageIdentity.IsPackaged
                && _stage is UpdateStage.Idle or UpdateStage.Failed)
            {
                _ = CheckAsync();
            }
        }
    }

    /// <summary>
    /// True while a scan is running, which is the one time an update must not start: installing
    /// closes the application, and closing it mid-scan throws away the report being built.
    /// </summary>
    public bool ApplicationBusy
    {
        get => _applicationBusy;
        set
        {
            if (_applicationBusy == value)
            {
                return;
            }

            _applicationBusy = value;
            Notify(nameof(CanStartInstall));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    // ---- The check ---------------------------------------------------------

    private async Task CheckAsync()
    {
        Stage = UpdateStage.Checking;

        if (!ReleaseVersion.TryParse(Scanner.Version, out var current))
        {
            // Nothing can be compared, so nothing is claimed. Silent for the same reason a
            // failed check is: this is our problem rather than the reader's, and a strip
            // across the window saying so helps nobody.
            Detail = $"This build's own version ({Scanner.Version}) could not be read.";
            Stage = UpdateStage.Idle;

            return;
        }

        UpdateCheckResult result;

        try
        {
            using var http = GitHubReleases.CreateClient();
            result = await GitHubReleases.CheckAsync(http, current).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            result = UpdateCheckResult.Failed(ex.Message);
        }

        // The check starts from a constructor, which can run before the dispatcher is pumping,
        // so the continuation is not guaranteed to be back on the UI thread. Same reason as
        // MainViewModel.DetectLocalCliAsync.
        Post(() => Apply(result));
    }

    private void Apply(UpdateCheckResult result)
    {
        switch (result.Outcome)
        {
            case UpdateCheckOutcome.UpdateAvailable when result.Update is { } available:
                _update = available;
                _dismissed = string.Equals(
                    _settings.DismissedVersion, available.Version.ToString(), StringComparison.Ordinal);
                Detail = DescribeAvailable(available);
                Stage = UpdateStage.Available;
                break;

            case UpdateCheckOutcome.CouldNotCheck:
                // Not shown. Being unable to reach GitHub is not the reader's problem and is
                // not worth a strip across the window; the version in the title bar is still
                // true and the scan is unaffected.
                Detail = result.Detail ?? string.Empty;
                Stage = UpdateStage.Idle;
                break;

            default:
                Detail = string.Empty;
                Stage = UpdateStage.Current;
                break;
        }
    }

    private string DescribeAvailable(AvailableUpdate available)
    {
        var published = available.Release.Published is { } date
            ? $", published {date.ToLocalTime().ToString("d MMMM yyyy", CultureInfo.CurrentCulture)}"
            : string.Empty;

        var line = $"You are running v{available.Current}. v{available.Version} is out{published}.";

        if (available.Executable is null)
        {
            return line + " That release has no VibeCheck.exe attached, so it has to be fetched by hand.";
        }

        // The refusal, stated where the button would be rather than as an absence. Today this
        // is the path every reader takes, because releases are not signed yet.
        return _capability.CanInstall
            ? line
            : $"{line} {_capability.Detail} Open the release page to fetch it by hand.";
    }

    // ---- Installing --------------------------------------------------------

    public bool CanStartInstall =>
        _stage == UpdateStage.Available
        && !ApplicationBusy
        && _capability is { CanInstall: true, TargetPath.Length: > 0 }
        && _update?.Executable is not null;

    private async Task InstallAsync()
    {
        if (!CanStartInstall
            || _update is not { Executable: { } asset } update
            || _capability.TargetPath is not { Length: > 0 } target)
        {
            return;
        }

        _cancellation = new CancellationTokenSource();

        var staged = $"{target}.{update.Version}{UpdateInstall.DownloadSuffix}";

        try
        {
            Progress = 0;
            Detail = $"Downloading v{update.Version}.";
            Stage = UpdateStage.Downloading;

            using var http = UpdateDownload.CreateClient();

            var build = await UpdateDownload.FetchAsync(
                http,
                asset,
                staged,
                new Progress<double>(fraction => Progress = fraction * 100),
                _cancellation.Token).ConfigureAwait(true);

            Detail = "Checking who signed it.";
            Stage = UpdateStage.Verifying;

            // Off the UI thread: verification builds a certificate chain and can go to the
            // network for revocation, which would otherwise freeze the window.
            var refusal = await Task.Run(() => UpdateInstall.Reject(build.Path, _capability))
                .ConfigureAwait(true);

            if (refusal is not null)
            {
                Discard(staged);
                Fail(refusal);
                return;
            }

            UpdateInstall.Replace(build.Path, target);

            Relaunch(target);
        }
        catch (OperationCanceledException)
        {
            Discard(staged);
            Detail = DescribeAvailable(update);
            Stage = UpdateStage.Available;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException
                                      or UnauthorizedAccessException or InvalidOperationException)
        {
            Discard(staged);
            Fail($"The update could not be installed. {ex.Message}");
        }
        finally
        {
            _cancellation?.Dispose();
            _cancellation = null;
        }
    }

    /// <summary>
    /// Starts the build that has just taken this one's place, and closes this one.
    /// </summary>
    /// <remarks>
    /// The path is the application's own location rather than anything that came off the
    /// network, and the file at it has been verified before reaching here.
    /// </remarks>
    private void Relaunch(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            // Installed but not restarted, which is worth saying: the window about to close
            // would otherwise be the last thing the reader saw.
            MessageBox.Show(
                $"VibeCheck was updated but could not restart itself.\n\n{ex.Message}",
                "VibeCheck",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        Application.Current?.Shutdown();
    }

    private static void Discard(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void OpenReleasePage()
    {
        var url = _update?.Release.PageUrl ?? GitHubReleases.ReleasesPageUrl;

        // Same check as the advisory links on the results screen, and for the same reason: this
        // address arrived in a response rather than from this codebase.
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(uri.ToString()) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception)
        {
        }
    }

    /// <summary>
    /// Puts the banner away and remembers which version was waved away, so the same one is not
    /// announced on every launch until the end of time.
    /// </summary>
    private void Dismiss()
    {
        if (_update is { } update)
        {
            _settings = _settings with { DismissedVersion = update.Version.ToString() };
            UpdateSettingsStore.Save(_settings);
        }

        _dismissed = true;
        Notify(nameof(IsVisible));
    }

    private void Fail(string detail)
    {
        Detail = detail;
        Stage = UpdateStage.Failed;
    }

    // ---- What the banner shows ---------------------------------------------

    private UpdateStage Stage
    {
        get => _stage;
        set
        {
            if (_stage == value)
            {
                return;
            }

            _stage = value;

            foreach (var name in new[]
                     {
                         nameof(IsVisible), nameof(Headline), nameof(IsWorking), nameof(ShowProgress),
                         nameof(CanStartInstall), nameof(ShowInstall), nameof(ShowReleasePage),
                         nameof(ReleasePageLabel), nameof(ShowDismiss), nameof(IsFailure),
                     })
            {
                Notify(name);
            }

            CommandManager.InvalidateRequerySuggested();
        }
    }

    /// <summary>
    /// Whether the strip appears at all. Silent in every state except the two worth
    /// interrupting for: a version exists that this one is not, and an attempt to fetch it
    /// went wrong.
    /// </summary>
    public bool IsVisible =>
        _stage switch
        {
            UpdateStage.Available => !_dismissed,
            UpdateStage.Downloading or UpdateStage.Verifying or UpdateStage.Failed => true,
            _ => false,
        };

    public string Headline => _stage switch
    {
        UpdateStage.Available => "A new version is available",
        UpdateStage.Downloading => $"Downloading v{_update?.Version}",
        UpdateStage.Verifying => "Verifying the download",
        UpdateStage.Failed => "The update was not installed",
        _ => string.Empty,
    };

    public string Detail
    {
        get => _detail;
        private set
        {
            if (_detail == value)
            {
                return;
            }

            _detail = value;
            Notify(nameof(Detail));
        }
    }

    public bool IsWorking => _stage is UpdateStage.Downloading or UpdateStage.Verifying;

    public bool ShowProgress => _stage == UpdateStage.Downloading;

    public bool IsFailure => _stage == UpdateStage.Failed;

    /// <summary>Only offered when it would actually work; the release page is offered regardless.</summary>
    public bool ShowInstall =>
        _stage == UpdateStage.Available && _capability.CanInstall && _update?.Executable is not null;

    public bool ShowReleasePage => _stage is UpdateStage.Available or UpdateStage.Failed;

    /// <summary>
    /// The same button reads differently depending on whether it is the way to update or
    /// merely the way to read what changed.
    /// </summary>
    public string ReleasePageLabel => ShowInstall ? "What's new" : "Open the release page";

    public bool ShowDismiss => _stage is UpdateStage.Available or UpdateStage.Failed;

    /// <summary>Progress from 0 to 100, which is what a ProgressBar wants.</summary>
    public double Progress
    {
        get => _progress;
        private set
        {
            if (Math.Abs(_progress - value) < 0.01)
            {
                return;
            }

            _progress = value;
            Notify(nameof(Progress));
        }
    }

    public ICommand InstallCommand { get; }

    public ICommand OpenReleasePageCommand { get; }

    public ICommand DismissCommand { get; }

    public ICommand CancelCommand { get; }

    // ---- Plumbing ----------------------------------------------------------

    private static void Post(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;

        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(action);
        }
        else
        {
            action();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Notify([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
