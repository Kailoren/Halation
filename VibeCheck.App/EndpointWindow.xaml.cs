using System.Windows;

using VibeCheck.Core.DeepPass;

namespace VibeCheck.App;

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

        Loaded += (_, _) => UrlBox.Focus();
    }

    /// <summary>
    /// What the reader settled on, or null when they cleared it. Only meaningful when the dialog
    /// returned true.
    /// </summary>
    public DeepPassEndpointSettings? Settings { get; private set; }

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
