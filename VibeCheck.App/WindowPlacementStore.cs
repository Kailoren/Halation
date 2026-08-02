using System.Globalization;
using System.IO;
using System.Windows;

namespace VibeCheck.App;

/// <summary>Where the window was last time, and how big.</summary>
public sealed record WindowPlacement
{
    public required double Left { get; init; }

    public required double Top { get; init; }

    public required double Width { get; init; }

    public required double Height { get; init; }

    public required bool Maximised { get; init; }
}

/// <summary>
/// Remembers the window's position and size between launches.
/// </summary>
/// <remarks>
/// <para>
/// A plain file beside the audience choice, with no protection: the worst outcome of tampering
/// is a badly placed window. Any failure to read or write is swallowed, because a preference
/// that cannot be saved is not worth refusing to start over.
/// </para>
/// <para>
/// <b>The restored position is validated against the screens that exist now.</b> A window
/// remembered on a second monitor, or on a laptop docked at a different resolution, restores
/// to coordinates that are no longer visible, and the application then appears not to launch
/// at all. That is indistinguishable from a crash to the person it happens to, and it happens
/// on the day their setup changes rather than the day the feature shipped.
/// </para>
/// </remarks>
public static class WindowPlacementStore
{
    /// <summary>
    /// How much of the window has to land on a screen for the position to be kept. A sliver
    /// is enough to drag it back with, which is all this needs to guarantee.
    /// </summary>
    private const double MinimumVisible = 120;

    private static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VibeCheck",
        "window");

    public static WindowPlacement? Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            var parts = File.ReadAllText(Path).Split(',');

            if (parts.Length != 5)
            {
                return null;
            }

            double? Number(int index) =>
                double.TryParse(parts[index], NumberStyles.Float, CultureInfo.InvariantCulture,
                    out var value) && double.IsFinite(value)
                    ? value
                    : null;

            if (Number(0) is not { } left || Number(1) is not { } top
                || Number(2) is not { } width || Number(3) is not { } height)
            {
                return null;
            }

            // A zero or negative size would restore an invisible window, which reads exactly
            // like a failure to start.
            if (width < 200 || height < 200)
            {
                return null;
            }

            return new WindowPlacement
            {
                Left = left,
                Top = top,
                Width = width,
                Height = height,
                Maximised = parts[4].Trim() == "1",
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or FormatException)
        {
            return null;
        }
    }

    public static void Save(Window window)
    {
        ArgumentNullException.ThrowIfNull(window);

        try
        {
            // RestoreBounds rather than the live properties. While maximised or minimised those
            // describe the current state, so saving them would restore a maximised window to
            // the size of the screen it was maximised on, and a minimised one to nothing.
            var bounds = window.WindowState == WindowState.Normal
                ? new Rect(window.Left, window.Top, window.Width, window.Height)
                : window.RestoreBounds;

            if (bounds.IsEmpty || !double.IsFinite(bounds.Left) || !double.IsFinite(bounds.Top))
            {
                return;
            }

            var directory = System.IO.Path.GetDirectoryName(Path);

            if (directory is not null)
            {
                Directory.CreateDirectory(directory);
            }

            // Minimised is deliberately not remembered as such: nobody wants an application
            // that starts minimised because that is how they last closed it.
            var maximised = window.WindowState == WindowState.Maximized ? "1" : "0";

            File.WriteAllText(Path, string.Join(',',
            [
                bounds.Left.ToString(CultureInfo.InvariantCulture),
                bounds.Top.ToString(CultureInfo.InvariantCulture),
                bounds.Width.ToString(CultureInfo.InvariantCulture),
                bounds.Height.ToString(CultureInfo.InvariantCulture),
                maximised,
            ]));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not worth failing a close over.
        }
    }

    /// <summary>
    /// Applies a stored placement, ignoring one that would put the window where it cannot be
    /// seen. Falls back to the window's declared defaults, which is what happens on first run.
    /// </summary>
    public static void Apply(Window window)
    {
        ArgumentNullException.ThrowIfNull(window);

        if (Load() is not { } placement || !IsReachable(placement))
        {
            // Centred rather than left to Windows. With no stored position the window's own
            // Left and Top are NaN, and the default startup location is Manual, so Windows
            // cascades it from the corner of the primary screen. That is where a first run
            // lands and where a discarded placement lands, and neither deserves it.
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            return;
        }

        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = placement.Left;
        window.Top = placement.Top;
        window.Width = placement.Width;
        window.Height = placement.Height;

        if (placement.Maximised)
        {
            window.WindowState = WindowState.Maximized;
        }
    }

    /// <summary>
    /// Whether enough of the remembered rectangle overlaps a screen that exists now.
    /// </summary>
    /// <remarks>
    /// Measured against the virtual screen rather than any single monitor, so a window spanning
    /// two of them is not rejected for sitting on neither. WPF exposes the virtual desktop in
    /// device-independent units through <see cref="SystemParameters"/>, which is the same space
    /// the saved coordinates are in, so no DPI conversion is involved.
    /// </remarks>
    private static bool IsReachable(WindowPlacement placement)
    {
        var virtualScreen = new Rect(
            SystemParameters.VirtualScreenLeft,
            SystemParameters.VirtualScreenTop,
            SystemParameters.VirtualScreenWidth,
            SystemParameters.VirtualScreenHeight);

        var window = new Rect(placement.Left, placement.Top, placement.Width, placement.Height);

        window.Intersect(virtualScreen);

        // The title bar is what a person grabs, so the overlap has to include enough of the
        // top edge to be usable rather than merely non-zero somewhere off the bottom.
        return !window.IsEmpty
               && window.Width >= MinimumVisible
               && window.Height >= MinimumVisible
               && window.Top <= placement.Top + 40;
    }
}
