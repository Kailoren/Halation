using System.IO;
using System.Windows;

namespace VibeCheck.App;

public partial class App : Application
{
    /// <summary>
    /// A path passed on the command line is scanned on startup.
    /// </summary>
    /// <remarks>
    /// Lets the application be wired into Explorer's "Send to" menu or a shortcut, so a
    /// downloaded file can be checked without opening the tool first and dragging it in.
    /// </remarks>
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Without this an unhandled exception closes the window with no explanation, which
        // is indistinguishable from the application simply refusing to start.
        DispatcherUnhandledException += (_, args) =>
        {
            ReportCrash(args.Exception);
            args.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            ReportCrash(args.ExceptionObject as Exception);

        var path = e.Args.FirstOrDefault(a => !a.StartsWith('-'));

        if (path is null || (!File.Exists(path) && !Directory.Exists(path)))
        {
            return;
        }

        // The window is constructed by StartupUri, so defer until it exists and is shown.
        Dispatcher.BeginInvoke(async () =>
        {
            if (MainWindow?.DataContext is MainViewModel model)
            {
                model.Isolate = e.Args.Contains("--isolate", StringComparer.OrdinalIgnoreCase);
                await model.ScanAsync(path);
            }
        });
    }

    private static void ReportCrash(Exception? exception)
    {
        if (exception is null)
        {
            return;
        }

        var log = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "VibeCheck",
            "crash.log");

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(log)!);
            File.AppendAllText(log, $"{DateTimeOffset.Now:O}\n{exception}\n\n");
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        MessageBox.Show(
            $"{exception.GetType().Name}: {exception.Message}\n\nDetails written to:\n{log}",
            "VibeCheck encountered a problem",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }
}
