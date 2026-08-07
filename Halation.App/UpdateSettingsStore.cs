using System.IO;

namespace Halation.App;

/// <summary>What the reader has decided about update checks.</summary>
public sealed record UpdateSettings
{
    /// <summary>
    /// Whether to ask GitHub what has been published, at startup.
    /// </summary>
    /// <remarks>
    /// On by default and switchable, for the same reason the dependency check is: this
    /// application's standing claim is that it says what leaves the machine, and a connection
    /// made on every launch that could not be turned off would be an exception to it.
    /// </remarks>
    public bool CheckOnStartup { get; init; } = true;

    /// <summary>The version the reader has already been told about and waved away.</summary>
    public string? DismissedVersion { get; init; }
}

/// <summary>
/// Reads and writes the update preferences.
/// </summary>
/// <remarks>
/// A plain text file with no protection, like <see cref="AudienceStore"/> beside it. The worst
/// outcome of tampering is being told about a version twice, or not being told about one.
/// </remarks>
public static class UpdateSettingsStore
{
    private static string Path => AppData.PathTo("updates");

    public static UpdateSettings Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return new UpdateSettings();
            }

            var check = true;
            string? dismissed = null;

            foreach (var line in File.ReadAllLines(Path))
            {
                var separator = line.IndexOf('=');

                if (separator <= 0)
                {
                    continue;
                }

                var key = line[..separator].Trim();
                var value = line[(separator + 1)..].Trim();

                switch (key)
                {
                    case "check":
                        check = value != "off";
                        break;

                    case "dismissed" when value.Length > 0:
                        dismissed = value;
                        break;
                }
            }

            return new UpdateSettings { CheckOnStartup = check, DismissedVersion = dismissed };
        }
        catch (IOException)
        {
            return new UpdateSettings();
        }
        catch (UnauthorizedAccessException)
        {
            return new UpdateSettings();
        }
    }

    public static void Save(UpdateSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = System.IO.Path.GetDirectoryName(Path);

            if (directory is not null)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllLines(Path,
            [
                $"check={(settings.CheckOnStartup ? "on" : "off")}",
                $"dismissed={settings.DismissedVersion ?? string.Empty}",
            ]);
        }
        catch (IOException)
        {
            // A preference that cannot be saved is not worth interrupting anything for. The
            // banner reappears next time, which is the failure that costs least.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
