using System.IO;
using System.Windows;

using Halation.Core.Rules;
using Halation.Core.Update;

namespace Halation.App;

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

        // After the handlers above, so a fault in here reaches the crash dialog rather than
        // closing the process with nothing on screen. Before anything reads a setting, which
        // StartupUri guarantees: the window is constructed once this returns.
        SettingsMigration.Carry(AppData.LegacyDirectory, AppData.Directory);

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
                await model.ScanAsync(path);
            }
        });
    }

    /// <summary>Ceiling on the crash log, past which it starts again rather than growing.</summary>
    private const long MaxCrashLogBytes = 256 * 1024;

    private static void ReportCrash(Exception? exception)
    {
        if (exception is null)
        {
            return;
        }

        var log = AppData.PathTo("crash.log");

        // Scrubbed and capped. This file is named in the dialog below, which is an invitation to
        // attach it to a bug report, and an exception from a third-party SDK is text this
        // codebase did not write. The same argument as everywhere else the reader's own key
        // could travel; this path was the one that got missed. See Redaction.Scrub.
        var entry = Redaction.Scrub($"{DateTimeOffset.Now:O}\n{exception}\n\n");

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(log)!);

            // Kept to the last few crashes rather than appended to forever. A log nobody
            // truncates is a slow leak of paths and stack traces from every scan ever run.
            if (File.Exists(log) && new FileInfo(log).Length > MaxCrashLogBytes)
            {
                File.WriteAllText(log, entry);
            }
            else
            {
                File.AppendAllText(log, entry);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        MessageBox.Show(
            $"{Redaction.Scrub($"{exception.GetType().Name}: {exception.Message}")}"
            + $"\n\nDetails written to:\n{log}",
            "VibeCheck encountered a problem",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }
}
