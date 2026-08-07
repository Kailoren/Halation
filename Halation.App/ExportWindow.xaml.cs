using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

using Halation.Core.Model;

namespace Halation.App;

/// <summary>
/// Asks which of the exports the reader wants.
/// </summary>
/// <remarks>
/// <para>
/// The results screen used to carry a button per format. That put the most consequential choice
/// in the product, whether a file may be published, into the difference between two adjacent
/// buttons with similar names, and gave it no room to say what the difference was.
/// </para>
/// <para>
/// A dialog on the pattern of <see cref="ScanSetupWindow"/> instead, so each option can carry a
/// sentence saying what is in it. Adding the scorecard made this necessary as well as tidier:
/// four buttons in a row would not have fitted the header at all.
/// </para>
/// </remarks>
public partial class ExportWindow : Window
{
    public ExportWindow(string artifactName)
    {
        InitializeComponent();

        ArtifactName.Text = artifactName;

        Choices =
        [
            .. ExportFormats.All.Select(f => new ExportChoice(f, this)),
        ];

        // Markdown first and selected, because it is the one somebody wanting "the report"
        // means, and a dialog that opens with nothing chosen makes the reader work to say the
        // obvious thing.
        Choices[0].IsSelected = true;

        Formats.ItemsSource = Choices;
    }

    internal List<ExportChoice> Choices { get; }

    /// <summary>The chosen format, or null when the reader backed out.</summary>
    public ExportFormat? Chosen { get; private set; }

    /// <summary>Reflects a pick onto every row, so the group shows one answer.</summary>
    internal void Select(ExportFormat format)
    {
        foreach (var choice in Choices)
        {
            choice.Reflect(format);
        }
    }

    private void OnExport(object sender, RoutedEventArgs e)
    {
        Chosen = Choices.FirstOrDefault(c => c.IsSelected)?.Format;
        DialogResult = Chosen is not null;
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        Chosen = null;
        DialogResult = false;
    }
}

/// <summary>One row in the chooser.</summary>
internal sealed class ExportChoice(ExportFormat format, ExportWindow owner) : INotifyPropertyChanged
{
    private bool _selected;

    public ExportFormat Format { get; } = format;

    public string Label { get; } = format.Label();

    public string Description { get; } = format.Description();

    /// <summary>
    /// Whether this one carries the reader's source, said in three words beside the name.
    /// </summary>
    public string CodeNote { get; } = format.CarriesYourCode()
        ? "contains your code"
        : "safe to publish";

    public Brush CodeNoteBrush { get; } = format.CarriesYourCode()
        ? (Brush)Application.Current.Resources["High"]
        : (Brush)Application.Current.Resources["Good"];

    public bool IsSelected
    {
        get => _selected;
        set
        {
            if (_selected == value)
            {
                return;
            }

            _selected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));

            if (value)
            {
                owner.Select(Format);
            }
        }
    }

    /// <summary>Clears this row unless it is the one that was picked.</summary>
    internal void Reflect(ExportFormat picked)
    {
        if (Format == picked || !_selected)
        {
            return;
        }

        _selected = false;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
