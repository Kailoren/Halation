using System.Windows;

namespace VibeCheck.App;

/// <summary>
/// Collects the deep pass API key.
/// </summary>
/// <remarks>
/// Deliberately plain. The key is the reader's billing credential, so it is entered into a
/// <c>PasswordBox</c>, never rendered back into the interface, and handed straight to
/// <see cref="ApiKeyStore"/> to be encrypted rather than held anywhere else.
/// </remarks>
public partial class ApiKeyWindow : Window
{
    public ApiKeyWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => KeyBox.Focus();
    }

    /// <summary>The entered key, or null when the reader chose to remove the stored one.</summary>
    public string? ApiKey { get; private set; }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var entered = KeyBox.Password;

        // Anthropic keys start sk-ant-. Checked so an obviously wrong paste is caught here
        // rather than surfacing as a failed scan later, but not validated any harder than
        // that: the API is the authority on whether a key works.
        if (!string.IsNullOrWhiteSpace(entered)
            && !entered.Trim().StartsWith("sk-ant-", StringComparison.Ordinal))
        {
            MessageBox.Show(
                "That does not look like an Anthropic API key. They begin with \"sk-ant-\".",
                "Check the key",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        ApiKey = string.IsNullOrWhiteSpace(entered) ? null : entered.Trim();
        DialogResult = true;
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        ApiKey = null;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
