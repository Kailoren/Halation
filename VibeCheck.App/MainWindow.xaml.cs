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

    private async void OnDrop(object sender, DragEventArgs e)
    {
        _model.IsDragging = false;

        if (_model.State != AppState.Waiting || !e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            return;
        }

        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
        {
            await _model.ScanAsync(paths[0]);
        }
    }

    // ---- Browse ------------------------------------------------------------

    /// <summary>
    /// One picker covering both files and folders.
    /// </summary>
    /// <remarks>
    /// An installed application is a folder and a downloaded one is usually a single file,
    /// and the user should not have to decide which kind of picker to ask for. The folder
    /// dialog is offered first because it is the case a file dialog cannot cover at all.
    /// </remarks>
    private async void OnBrowse(object sender, RoutedEventArgs e)
    {
        var folder = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Choose an application folder (cancel to pick a single file instead)",
        };

        if (folder.ShowDialog() == true)
        {
            await _model.ScanAsync(folder.FolderName);
            return;
        }

        var file = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose an application",
            Filter = "Applications and archives|*.exe;*.dll;*.zip;*.asar;*.jar|All files|*.*",
        };

        if (file.ShowDialog() == true)
        {
            await _model.ScanAsync(file.FileName);
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
