using System.Globalization;
using System.Windows;

using VibeCheck.Core.DeepPass;

namespace VibeCheck.App;

/// <summary>One model already installed on this machine, as the button that selects it.</summary>
/// <param name="Tag">The model id to request.</param>
/// <param name="Endpoint">The runtime that has it.</param>
/// <param name="Label">Tag, size and whether it fits, in one line.</param>
public sealed record DetectedModelRow(string Tag, Uri Endpoint, string Label);

/// <summary>
/// Collects the endpoint, model and optional key for a deep pass answered by something other
/// than Anthropic.
/// </summary>
/// <remarks>
/// <para>
/// Three fields and a row of presets, because the only genuinely hard part of this setting is
/// remembering somebody else's URL. The presets carry the paths that are easy to get wrong and
/// impossible to debug from the interface, and the model is left to the reader wherever naming
/// one would be a guess about a catalogue that turns over faster than this application ships.
/// </para>
/// <para>
/// The URL is normalised in front of the reader rather than on the way to the request. This is
/// the setting that decides where recovered source code is sent, so the box showing one address
/// while another is requested would be precisely the quiet substitution this tool exists to
/// report in other people's software.
/// </para>
/// </remarks>
public partial class EndpointWindow : Window
{
    private readonly DeepPassEndpointSettings? _existing;

    /// <summary>
    /// Whether the key already on disk still applies to what is in the box.
    /// </summary>
    /// <remarks>
    /// A stored key is never displayed, so an empty field has to mean "keep it". That is only
    /// safe while the endpoint is the same one: carrying a key across a change of host would
    /// send a credential bought from one provider to another provider's server, which is a
    /// worse outcome than making somebody paste it again.
    /// </remarks>
    private bool _carriesStoredKey;

    public EndpointWindow(DeepPassEndpointSettings? existing)
    {
        InitializeComponent();

        _existing = existing;
        _carriesStoredKey = !string.IsNullOrWhiteSpace(existing?.Key);

        PresetList.ItemsSource = DeepPassEndpoints.Presets;

        if (existing is not null)
        {
            UrlBox.Text = existing.Endpoint.ToString();
            ModelBox.Text = existing.Model;
        }

        RemoveButton.Visibility = existing is null ? Visibility.Collapsed : Visibility.Visible;

        RefreshKeyNote();

        // Sized to content, so without a ceiling a machine with a dozen models installed pushes
        // the buttons off the bottom of the screen. The ScrollViewer takes over past this.
        MaxHeight = SystemParameters.WorkArea.Height * 0.92;

        ShowHardware();

        Loaded += (_, _) =>
        {
            UrlBox.Focus();
            _ = DetectAsync();
        };

        // On close rather than on save, because how much memory the card has is a fact about the
        // machine and not part of the endpoint decision. Cancelling the dialog should not throw
        // away a correction the reader made to it.
        Closed += (_, _) => RememberHardware();
    }

    /// <summary>
    /// What the reader settled on, or null when they cleared it. Only meaningful when the dialog
    /// returned true.
    /// </summary>
    public DeepPassEndpointSettings? Settings { get; private set; }

    // ---- This machine ------------------------------------------------------

    private GraphicsAdapter? _adapter;
    private long _videoBytes;
    private long _systemBytes;
    private IReadOnlyList<LocalRuntime> _runtimes = [];

    /// <summary>What was detected about the card, with the reader's own figure taking priority.</summary>
    private void ShowHardware()
    {
        _adapter = GraphicsMemory.Detect();
        _systemBytes = GraphicsMemory.SystemBytes();

        var corrected = HardwareStore.Load();

        _videoBytes = corrected ?? _adapter?.VideoBytes ?? 0;

        // Named even when there is no card, because system memory is what a model runs in then,
        // and a machine with plenty of it is in a better position than one without.
        AdapterName.Text = _adapter is not null
            ? $"{_adapter.Name}, {LocalModelGuide.Gigabytes(_systemBytes)} system memory"
            : $"No graphics card found, {LocalModelGuide.Gigabytes(_systemBytes)} system memory";
        VideoMemoryBox.Text = _videoBytes > 0
            ? (_videoBytes / (double)(1024L * 1024 * 1024)).ToString("0.#", CultureInfo.CurrentCulture)
            : string.Empty;

        MemorySource.Text = corrected is not null ? "(your figure)"
            : _adapter is not null ? "(detected)"
            : "(not detected, please fill in)";

        HardwareAdvice.Text = LocalModelGuide.Advise(_videoBytes, _systemBytes);
    }

    /// <summary>
    /// Re-reads the box as the reader types, so the advice and the verdicts follow immediately.
    /// </summary>
    /// <remarks>
    /// Both cultures are tried. A reader on a European locale writes 11,5 and one on an English
    /// locale writes 11.5, and refusing either of them over a separator would be a silly place to
    /// stop being useful.
    /// </remarks>
    private void OnVideoMemoryChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (HardwareAdvice is null)
        {
            return;
        }

        var typed = VideoMemoryBox.Text;

        var parsed =
            double.TryParse(typed, NumberStyles.Float, CultureInfo.CurrentCulture, out var value)
            || double.TryParse(typed, NumberStyles.Float, CultureInfo.InvariantCulture, out value);

        _videoBytes = parsed && value > 0 ? (long)(value * 1024 * 1024 * 1024) : 0;

        MemorySource.Text = _adapter is not null && _videoBytes == _adapter.VideoBytes
            ? "(detected)"
            : "(your figure)";

        HardwareAdvice.Text = LocalModelGuide.Advise(_videoBytes, _systemBytes);
        ShowDetection();
    }

    /// <summary>
    /// Keeps a corrected figure, and only a corrected one.
    /// </summary>
    /// <remarks>
    /// Storing a figure that merely matches what was detected would freeze it: the reader
    /// upgrades their card and this application would go on advising them for the old one
    /// forever, with nothing on screen to say why.
    /// </remarks>
    private void RememberHardware() =>
        HardwareStore.Save(
            _videoBytes > 0 && _videoBytes != (_adapter?.VideoBytes ?? 0) ? _videoBytes : null);

    // ---- What is already running -------------------------------------------

    private async Task DetectAsync()
    {
        _runtimes = await LocalRuntimeProbe.FindAsync().ConfigureAwait(true);

        ShowDetection();
    }

    /// <summary>
    /// Says what answered, lists what it has, and judges each against the card.
    /// </summary>
    /// <remarks>
    /// A runtime that is running with nothing installed gets different words from one that is
    /// not running at all. Collapsing those two would send somebody off to install what they
    /// already have, which is the most annoying possible way to be told to do nothing.
    /// </remarks>
    private void ShowDetection()
    {
        var rows = new List<(DetectedModelRow Row, ModelFit Fit, long Bytes)>();
        var many = _runtimes.Count > 1;

        foreach (var runtime in _runtimes)
        {
            foreach (var model in runtime.Models)
            {
                var cloud = LocalModelGuide.IsCloudModel(model.Id);
                var fit = LocalModelGuide.Judge(model.Bytes, _videoBytes);

                var label = many ? $"{runtime.Name}  ·  {model.Id}" : model.Id;

                // A cloud model reports no size because it is not here. Left to the ordinary
                // path it would read "size unknown", which invites the reader to assume it is
                // simply an unlabelled local model.
                if (cloud)
                {
                    label += "  ·  runs on Ollama's servers, your code is uploaded";
                }
                else
                {
                    if (model.Bytes > 0)
                    {
                        label += $"  ·  {LocalModelGuide.Gigabytes(model.Bytes)}";
                    }

                    if (fit != ModelFit.Unknown)
                    {
                        label += $"  ·  {LocalModelGuide.Describe(fit)}";
                    }
                }

                // Said out loud rather than only sorted on. Somebody who pulled a chat model for
                // something else should not have to work out why the list put it last.
                if (!LocalModelGuide.LooksCodeCapable(model.Id))
                {
                    label += "  ·  general model, weaker at reading code";
                }

                rows.Add((new DetectedModelRow(model.Id, runtime.Endpoint, label), fit, model.Bytes));
            }
        }

        // Ordered so the top row is the one worth clicking. Fit first, because a model that does
        // not fit is slow whatever else it is; then code models ahead of general ones, because
        // this is a code review and size is a poor proxy for that at similar sizes; then the
        // largest, since a bigger model that still fits reasons better about the same file.
        // Sorting on size alone put a general chat model above a coder one purely for being
        // 200MB larger, which is the row somebody would have clicked.
        DetectedModels.ItemsSource = rows
            .OrderBy(r => r.Fit switch
            {
                ModelFit.Comfortable => 0,
                ModelFit.Tight => 1,
                ModelFit.Unknown => 2,
                _ => 3,
            })
            .ThenBy(r => LocalModelGuide.LooksCodeCapable(r.Row.Tag) ? 0 : 1)
            .ThenByDescending(r => r.Bytes)
            .Select(r => r.Row)
            .ToList();

        var recommended = LocalModelGuide.Recommend(_videoBytes) ?? LocalModelGuide.Choices[0];

        PullCommand.Text = recommended.PullCommand;

        // What the recommendation costs, said where the recommendation is made. A reader deciding
        // whether to take it is deciding whether to spend the download, and the figure was
        // carried on the choice all along without ever reaching the screen.
        PullSize.Text = $"{LocalModelGuide.Gigabytes(recommended.DownloadBytes)} to download";
        ContextCaution.Visibility = _runtimes.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        if (_runtimes.Count == 0)
        {
            DetectionStatus.Text =
                "Neither Ollama nor LM Studio is answering on this machine. Install one, run the "
                + "command below to fetch a model, then open this window again. Nothing about "
                + "your code leaves the machine on that route.";
            PullRow.Visibility = Visibility.Visible;

            return;
        }

        var names = string.Join(" and ", _runtimes.Select(r => r.Name));

        if (rows.Count == 0)
        {
            DetectionStatus.Text =
                $"{names} is running here but has no models yet. This command fetches the "
                + "largest one your card can hold:";
            PullRow.Visibility = Visibility.Visible;

            return;
        }

        DetectionStatus.Text =
            $"{names} is running on this machine. Choose one of its models and the fields below "
            + "fill themselves in:";

        // Offered even when something is installed, because what is installed is often a chat
        // model somebody pulled for something else, and the verdicts above may all read badly.
        PullRow.Visibility = Visibility.Visible;
    }

    /// <summary>Takes a detected model, which is the one selection guaranteed to be spelled right.</summary>
    private void OnUseDetected(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not DetectedModelRow row)
        {
            return;
        }

        UrlBox.Text = row.Endpoint.ToString();
        ModelBox.Text = row.Tag;

        // Nothing on this machine wants a key, and one left in the box would be sent to it.
        // Ollama's cloud models are no exception: they authenticate with the credential the
        // runtime holds from ollama signin, which never passes through here.
        KeyBox.Clear();
        _carriesStoredKey = _carriesStoredKey && SameHostAsStored(UrlBox.Text);
        RefreshKeyNote();

        PresetNote.Text = LocalModelGuide.IsCloudModel(row.Tag)
            ? "This one is not on this machine. Ollama forwards it to ollama.com on your plan, so "
              + "the files are uploaded. It buys a much larger model than your card could hold."
            : "Running on this machine. The files never leave it, nothing is charged, and it "
              + "works with the network unplugged.";

        Hide(Problem);
    }

    private void OnCopyPull(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(PullCommand.Text);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Another process holds the clipboard. The command is on screen and selectable, so
            // this is a convenience failing rather than the reader losing anything.
        }
    }

    /// <summary>Fills both fields from a provider, and drops anything the old one carried.</summary>
    private void OnPreset(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not DeepPassEndpointPreset preset)
        {
            return;
        }

        UrlBox.Text = preset.Url;
        ModelBox.Text = preset.SuggestedModel ?? string.Empty;
        PresetNote.Text = preset.Note;

        // A key is bought from one provider and means nothing to another, so choosing a
        // different one clears both what is typed and what is stored.
        KeyBox.Clear();
        _carriesStoredKey = _carriesStoredKey && SameHostAsStored(preset.Url);
        RefreshKeyNote();

        Hide(Problem);

        // The model is the field a preset cannot fill in for most providers, so the caret goes
        // where the remaining question is.
        if (string.IsNullOrEmpty(ModelBox.Text))
        {
            ModelBox.Focus();
        }
    }

    /// <summary>
    /// Completes a pasted base URL as soon as the reader leaves the field.
    /// </summary>
    /// <remarks>
    /// Done here rather than at save time so that what is on screen is what will be requested
    /// before anybody commits to it, and so a paste that could not be read at all is visible
    /// immediately instead of at the end.
    /// </remarks>
    private void OnUrlLostFocus(object sender, RoutedEventArgs e)
    {
        if (DeepPassEndpoints.Normalise(UrlBox.Text) is not { } endpoint)
        {
            return;
        }

        UrlBox.Text = endpoint.ToString();

        if (_carriesStoredKey && !SameHostAsStored(UrlBox.Text))
        {
            _carriesStoredKey = false;
            RefreshKeyNote();
        }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        // An empty box and Save is how the key dialog clears a stored key, and it means the
        // same here rather than being an error to correct.
        if (string.IsNullOrWhiteSpace(UrlBox.Text))
        {
            Settings = null;
            DialogResult = true;

            return;
        }

        if (DeepPassEndpoints.Normalise(UrlBox.Text) is not { } endpoint)
        {
            Show("That is not an address VibeCheck can request. It should look like "
                 + "https://api.openai.com/v1 or http://localhost:11434/v1.");

            return;
        }

        UrlBox.Text = endpoint.ToString();

        // Asked of the backend rather than restated here. It is the thing that will refuse the
        // request, so it should be the thing that words the refusal.
        if (OpenAiCompatibleBackend.RejectEndpoint(endpoint) is { } problem)
        {
            Show(problem);

            return;
        }

        if (string.IsNullOrWhiteSpace(ModelBox.Text))
        {
            Show("Name the model to ask for. A chat-completions request has to say which model "
                 + "to use, and there is no default that would be right for both a local "
                 + "runtime and a hosted provider.");

            return;
        }

        Settings = new DeepPassEndpointSettings(endpoint, ModelBox.Text.Trim(), KeyToStore());
        DialogResult = true;
    }

    /// <summary>
    /// What to write for the key: what was typed, what was already there, or nothing.
    /// </summary>
    private string? KeyToStore()
    {
        if (!string.IsNullOrWhiteSpace(KeyBox.Password))
        {
            return KeyBox.Password.Trim();
        }

        return ForgetKey.IsChecked == true || !_carriesStoredKey ? null : _existing?.Key;
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        Settings = null;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    /// <summary>Whether a typed URL still points at the host the stored key was set up for.</summary>
    private bool SameHostAsStored(string? typed) =>
        _existing is not null
        && DeepPassEndpoints.Normalise(typed) is { } candidate
        && string.Equals(
            candidate.Host, _existing.Endpoint.Host, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Says what an empty key box will do, which depends on whether one is already stored.
    /// </summary>
    private void RefreshKeyNote()
    {
        ForgetKey.Visibility = _carriesStoredKey ? Visibility.Visible : Visibility.Collapsed;

        if (!_carriesStoredKey)
        {
            ForgetKey.IsChecked = false;
        }

        KeyNote.Text = _carriesStoredKey
            ? "A key is stored for this endpoint. It is not shown back, so leaving this empty "
              + "keeps it and typing a new one replaces it. Sent as a bearer token, encrypted "
              + "to your Windows account, and stored outside this application's folder."
            : "Left empty for a model on this machine, which has nothing to authenticate. Sent "
              + "as a bearer token, encrypted to your Windows account, and stored outside this "
              + "application's folder.";
    }

    private void Show(string problem)
    {
        Problem.Text = problem;
        Problem.Visibility = Visibility.Visible;
    }

    private static void Hide(UIElement element) => element.Visibility = Visibility.Collapsed;
}
