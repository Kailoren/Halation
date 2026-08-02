using System.IO;

using VibeCheck.Core.Model;

namespace VibeCheck.App;

/// <summary>
/// Remembers which of the two reports this person wants.
/// </summary>
/// <remarks>
/// <para>
/// Stored rather than asked per scan, because the answer is a fact about the reader rather
/// than about the artifact: someone checking their own builds is checking their own builds
/// every time. It is a plain file with no protection, unlike the API key beside it, because
/// the worst outcome of tampering is that somebody reads the wrong report.
/// </para>
/// <para>
/// The absence of the file is meaningful and is not a default. It means the question has not
/// been asked yet, which is what triggers asking it, so <see cref="Load"/> returns null rather
/// than guessing developer and quietly showing an end user the wrong document forever.
/// </para>
/// </remarks>
public static class AudienceStore
{
    private static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VibeCheck",
        "audience");

    /// <summary>The stored choice, or null when this person has not been asked yet.</summary>
    public static Audience? Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            return File.ReadAllText(Path).Trim() switch
            {
                nameof(Audience.EndUser) => Audience.EndUser,
                nameof(Audience.Developer) => Audience.Developer,

                // An unreadable value is treated as never having been asked, so the prompt
                // reappears rather than a silent default deciding on the reader's behalf.
                _ => null,
            };
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

    public static void Save(Audience audience)
    {
        try
        {
            var directory = System.IO.Path.GetDirectoryName(Path);
            if (directory is not null)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(Path, audience.ToString());
        }
        catch (IOException)
        {
            // A preference that cannot be saved is not worth failing a scan over. The prompt
            // simply asks again next time.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
