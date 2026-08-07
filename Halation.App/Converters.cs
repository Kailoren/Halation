using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

using Halation.Core.Model;

namespace Halation.App;

/// <summary>Maps a finding's severity onto the palette.</summary>
public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is Severity severity
            ? severity switch
            {
                Severity.Critical => "Critical",
                Severity.High => "High",
                Severity.Medium => "Medium",
                Severity.Low => "Low",
                _ => "Muted",
            }
            : "Muted";

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Maps a score band onto the palette.
/// </summary>
/// <remarks>
/// The one that matters is <see cref="ScoreBand.InsufficientCoverage"/>: it is grey, not
/// green. An artifact that could not be read must never be coloured like one that passed.
/// </remarks>
public sealed class BandBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is ScoreBand band
            ? band switch
            {
                ScoreBand.CriticalIssues => "Critical",
                ScoreBand.SeriousIssues => "High",
                ScoreBand.NeedsWork => "Medium",
                ScoreBand.NoKnownIssues => "Good",
                _ => "Unknown",
            }
            : "Unknown";

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class BoolToVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Visibility.Visible;
}

public sealed class InverseBoolToVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class NullToVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is null or "" ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class CountToVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
