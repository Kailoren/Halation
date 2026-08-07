using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Navigation;

namespace VibeCheck.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _model = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _model;

        // Published so a theme can stop animating something nobody can see. It goes through the
        // view model rather than being read off the window because a template trigger binds
        // against the DataContext, and a RelativeSource walk up to the Window from inside a
        // template silently resolves to nothing: the trigger simply never fires, which looks
        // exactly like a theme that chose not to animate. IsDragging already works this way and
        // this follows it.
        StateChanged += (_, _) => _model.IsMinimised = WindowState == WindowState.Minimized;

        // Applied before the window is shown, so it opens where it was left rather than
        // appearing centred and jumping. A remembered position that no longer lands on any
        // screen is discarded inside Apply; see WindowPlacementStore for why that matters more
        // than it sounds.
        WindowPlacementStore.Apply(this);

        // Closing rather than a state change, so a window dragged around during a session
        // is only written once.
        Closing += (_, _) => WindowPlacementStore.Save(this);
    }

    // ---- Window chrome -----------------------------------------------------

    private void OnMinimise(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximise(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    // ---- Drag and drop -----------------------------------------------------

    private void OnDragEnter(object sender, DragEventArgs e) => UpdateDrag(e);

    private void OnDragOver(object sender, DragEventArgs e) => UpdateDrag(e);

    private void OnDragLeave(object sender, DragEventArgs e) => _model.IsDragging = false;

    /// <summary>
    /// Accepts a drop only while idle, so a drag during a scan reads as refused rather than
    /// appearing to work and then being ignored.
    /// </summary>
    private void UpdateDrag(DragEventArgs e)
    {
        var acceptable = _model.State == AppState.Waiting
                         && e.Data.GetDataPresent(DataFormats.FileDrop);

        _model.IsDragging = acceptable;
        e.Effects = acceptable ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>
    /// Takes the drop and stops there. Starting the scan is a separate click, so the deep pass
    /// settings underneath can still be changed for the scan they are about to apply to.
    /// </summary>
    private void OnDrop(object sender, DragEventArgs e)
    {
        _model.IsDragging = false;

        if (_model.State != AppState.Waiting || !e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            return;
        }

        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
        {
            Choose(paths[0]);
        }
    }

    /// <summary>
    /// Takes an artifact and asks about it before scanning.
    /// </summary>
    /// <remarks>
    /// One path for all three ways in (drop, file picker, folder picker), so the question cannot
    /// be reached by one and skipped by another.
    /// </remarks>
    private async void Choose(string path)
    {
        _model.Select(path);

        var setup = new ScanSetupWindow(_model, path) { Owner = this };

        setup.ShowDialog();

        if (setup.StartRequested)
        {
            await _model.StartScanAsync();
            return;
        }

        _model.ClearSelection();
    }

    // ---- Browse ------------------------------------------------------------

    /// <summary>
    /// Picks a file.
    /// </summary>
    /// <remarks>
    /// One dialog, opened directly. It used to show the folder picker first and reach the file
    /// picker only when that was cancelled, so choosing a downloaded .exe, the common case,
    /// meant dismissing a dialog that was never wanted. Windows has no picker that takes either,
    /// so the honest arrangement is two buttons and no guessing about which one somebody meant.
    /// </remarks>
    private void OnBrowseFile(object sender, RoutedEventArgs e)
    {
        var file = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose an application",
            Filter = "Applications and archives|*.exe;*.dll;*.zip;*.asar;*.jar|All files|*.*",
        };

        if (file.ShowDialog() == true)
        {
            Choose(file.FileName);
        }
    }

    /// <summary>Picks an installed folder or a source tree, which a file dialog cannot reach.</summary>
    private void OnBrowseFolder(object sender, RoutedEventArgs e)
    {
        var folder = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Choose an application folder",
        };

        if (folder.ShowDialog() == true)
        {
            Choose(folder.FolderName);
        }
    }

    // ---- Deep pass key -----------------------------------------------------

    /// <summary>
    /// Collects the API key. A plain dialog rather than anything cleverer, and the entered
    /// value is never echoed back into the interface afterwards.
    /// </summary>
    private void OnSetApiKey(object sender, RoutedEventArgs e)
    {
        var dialog = new ApiKeyWindow { Owner = this };

        if (dialog.ShowDialog() == true)
        {
            _model.SetApiKey(dialog.ApiKey);
        }
    }

    /// <summary>
    /// Collects the endpoint the deep pass should go to when neither Anthropic route is wanted.
    /// </summary>
    /// <remarks>
    /// Opened with whatever is stored so the dialog can edit rather than only replace. The key
    /// is passed in and never rendered: the dialog needs to know one exists in order to decide
    /// what an empty field means, which is a different thing from showing it.
    /// </remarks>
    private void OnConfigureEndpoint(object sender, RoutedEventArgs e)
    {
        var dialog = new EndpointWindow(_model.Endpoint) { Owner = this };

        if (dialog.ShowDialog() == true)
        {
            _model.SetEndpoint(dialog.Settings);
        }
    }

    // ---- Links -------------------------------------------------------------

    /// <summary>
    /// Opens an advisory link.
    /// </summary>
    /// <remarks>
    /// The scheme is verified before launching, for exactly the reason the scanner reports
    /// applications that skip that check: these URLs arrive from advisory data, and handing
    /// an unvalidated string to the shell is the very finding this tool raises against others.
    /// </remarks>
    private void OnNavigate(object sender, RequestNavigateEventArgs e)
    {
        e.Handled = true;

        if (!Uri.TryCreate(e.Uri?.ToString(), UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(uri.ToString()) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception)
        {
            // A browser that will not launch is not worth interrupting the report for.
        }
    }
}
