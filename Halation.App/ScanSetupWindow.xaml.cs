using System.IO;
using System.Windows;

using VibeCheck.Core.Model;

namespace VibeCheck.App;

/// <summary>
/// The step between choosing an application and scanning it.
/// </summary>
/// <remarks>
/// <para>
/// Dropping a file used to start the scan on the spot, which put every decision that changes
/// what a scan means out of reach: the settings sit below the drop zone, so by the time a reader
/// had read them the scan they applied to had already run. This is that gap, made explicit.
/// </para>
/// <para>
/// A dialog rather than a panel on the waiting screen, because the waiting screen already
/// carries the drop zone, the deep pass card and the update strip, and the kind selector pushed
/// the drop zone past its own height. A modal also makes the sequence unambiguous: choose, then
/// describe, then scan.
/// </para>
/// </remarks>
public partial class ScanSetupWindow : Window
{
    private readonly MainViewModel _model;

    public ScanSetupWindow(MainViewModel model, string path)
    {
        ArgumentNullException.ThrowIfNull(model);

        _model = model;

        InitializeComponent();

        // The artifact's own name, not the full path: it is long, it is usually inside somebody's
        // user folder, and this window is the one they will screenshot if anything goes wrong.
        ArtifactName.Text = Path.GetFileName(
            path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        // The two readers are answering different questions. A developer describes what they
        // built; somebody checking a download describes what it claims to be, and the gap
        // between that claim and what the scan found is the whole point of asking them.
        KindPrompt.Text = ApplicationKinds.Prompt(model.Audience);
        KindNote.Text = ApplicationKinds.PromptNote(model.Audience);

        ReadyNote.Text = model.Audience == Core.Model.Audience.EndUser
            ? "Ready to scan. What this is meant to be decides which of its behaviours are "
              + "worth worrying about."
            : "Ready to scan. Telling VibeCheck what kind of application this is changes how "
              + "anything unusual is explained to you afterwards.";

        Kinds.ItemsSource = model.ApplicationKindChoices;
    }

    /// <summary>True when the reader chose to go ahead.</summary>
    public bool StartRequested { get; private set; }

    private void OnStart(object sender, RoutedEventArgs e)
    {
        StartRequested = true;
        DialogResult = true;
    }

    /// <summary>
    /// Backs out. Clears the declaration as well as the selection, because it described the
    /// application being abandoned and carrying it onto the next one would answer a question
    /// about that one which nobody was asked.
    /// </summary>
    private void OnChooseDifferent(object sender, RoutedEventArgs e)
    {
        _model.ChooseKind(Core.Model.ApplicationKind.Unstated);
        StartRequested = false;
        DialogResult = false;
    }
}
