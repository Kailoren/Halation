using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using VibeCheck.Core.DeepPass;

namespace VibeCheck.App;

/// <summary>
/// Where the deep pass should go when it is answered by something other than Anthropic.
/// </summary>
/// <param name="Endpoint">The exact chat-completions URL, as it will be requested.</param>
/// <param name="Model">
/// The model to ask for. Required rather than optional: a chat-completions request has to name
/// one, and there is no default that would be right for both a local runtime and a hosted
/// provider.
/// </param>
/// <param name="Key">The bearer token, or null for a local model that has nothing to check.</param>
public sealed record DeepPassEndpointSettings(Uri Endpoint, string Model, string? Key)
{
    /// <summary>How this endpoint is named on screen: by where the code goes.</summary>
    public string Description => DeepPassEndpoints.Describe(Endpoint, Model);

    /// <summary>Whether the model answering is on this machine, which changes what is uploaded.</summary>
    public bool IsLocal => Endpoint.IsLoopback;
}

/// <summary>
/// Stores the deep pass endpoint on this machine, encrypted to this Windows account.
/// </summary>
/// <remarks>
/// <para>
/// The same treatment as <see cref="ApiKeyStore"/>, and for the same reason: one of the three
/// fields is a billing credential. Encrypting the other two costs nothing and avoids a file that
/// names an internal inference server in plain text, which is not a secret but is not this
/// application's to leave lying about either.
/// </para>
/// <para>
/// Kept as one record rather than three files because the three are only meaningful together. A
/// URL with no model cannot be requested, and a key with no URL has nothing to authenticate to.
/// </para>
/// </remarks>
public static class EndpointStore
{
    private static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VibeCheck",
        "deep-pass-endpoint");

    /// <summary>The stored shape. Separate from the record above so the file is plain JSON.</summary>
    private sealed record Stored(string? Url, string? Model, string? Key);

    /// <summary>Returns the stored endpoint, or null when none is saved or it cannot be read.</summary>
    /// <remarks>
    /// A stored value that no longer parses, or that names a URL this application would refuse to
    /// send to, is treated as absent. Returning it would put a route on screen that the scan then
    /// declines, and the reader would have no way to tell which of the two was wrong.
    /// </remarks>
    public static DeepPassEndpointSettings? Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            var plaintext = ProtectedData.Unprotect(
                File.ReadAllBytes(Path), optionalEntropy: null, DataProtectionScope.CurrentUser);

            var stored = JsonSerializer.Deserialize<Stored>(Encoding.UTF8.GetString(plaintext));

            if (stored?.Url is null || string.IsNullOrWhiteSpace(stored.Model))
            {
                return null;
            }

            if (DeepPassEndpoints.Normalise(stored.Url) is not { } endpoint
                || OpenAiCompatibleBackend.RejectEndpoint(endpoint) is not null)
            {
                return null;
            }

            return new DeepPassEndpointSettings(endpoint, stored.Model.Trim(), stored.Key);
        }
        catch (CryptographicException)
        {
            // Written by a different account, or the profile was rebuilt. Absent rather than
            // fatal: the deep pass is optional.
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Saves an endpoint, or clears the stored one when given null.</summary>
    public static void Save(DeepPassEndpointSettings? settings)
    {
        try
        {
            if (settings is null)
            {
                if (File.Exists(Path))
                {
                    File.Delete(Path);
                }

                return;
            }

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);

            var json = JsonSerializer.Serialize(
                new Stored(
                    settings.Endpoint.ToString(),
                    settings.Model,
                    string.IsNullOrWhiteSpace(settings.Key) ? null : settings.Key.Trim()));

            File.WriteAllBytes(
                Path,
                ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(json),
                    optionalEntropy: null,
                    DataProtectionScope.CurrentUser));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (CryptographicException) { }
    }
}
