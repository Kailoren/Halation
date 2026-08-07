using System.IO;

using Halation.Core.Model;

namespace Halation.App;

/// <summary>
/// Remembers which of the two reports this person wants.
/// </summary>
/// <remarks>
/// A plain file with no protection, unlike the key beside it, because the worst outcome of
/// tampering is reading the wrong report. <b>Its absence is meaningful and is not a default</b>:
/// it means the question has not been asked, so <see cref="Load"/> returns null rather than
/// guessing developer and showing an end user the wrong document forever.
/// </remarks>
public static class AudienceStore
{
    private static string Path => AppData.PathTo("audience");

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
