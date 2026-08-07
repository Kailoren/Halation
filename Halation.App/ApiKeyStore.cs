using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Halation.App;

/// <summary>
/// Stores the optional deep pass API key on this machine, encrypted to this Windows account.
/// </summary>
/// <remarks>
/// DPAPI with <see cref="DataProtectionScope.CurrentUser"/>, so the ciphertext is readable only
/// by the account that wrote it and no key material is invented here. Kept outside the install
/// directory: a scanner that left a billing credential somewhere a later scan could report
/// would be indefensible.
/// </remarks>
public static class ApiKeyStore
{
    private static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VibeCheck",
        "deep-pass.key");

    /// <summary>Returns the stored key, or null when none is saved or it cannot be decrypted.</summary>
    public static string? Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            var plaintext = ProtectedData.Unprotect(
                File.ReadAllBytes(Path), optionalEntropy: null, DataProtectionScope.CurrentUser);

            return Encoding.UTF8.GetString(plaintext);
        }
        catch (CryptographicException)
        {
            // Written by a different account, or the profile was rebuilt. Treat as absent
            // rather than failing the app: the deep pass is optional.
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

    /// <summary>Saves a key, or clears the stored one when given null or blank.</summary>
    public static void Save(string? key)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                if (File.Exists(Path))
                {
                    File.Delete(Path);
                }

                return;
            }

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);

            var ciphertext = ProtectedData.Protect(
                Encoding.UTF8.GetBytes(key.Trim()), optionalEntropy: null, DataProtectionScope.CurrentUser);

            File.WriteAllBytes(Path, ciphertext);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (CryptographicException) { }
    }

    /// <summary>
    /// Renders a key for display without showing it. The reader needs to confirm which key is
    /// stored, not read it back out of the interface.
    /// </summary>
    public static string Describe(string? key) =>
        string.IsNullOrWhiteSpace(key) || key.Length < 12
            ? "not set"
            : $"{key[..8]}...{key[^4..]}";
}
