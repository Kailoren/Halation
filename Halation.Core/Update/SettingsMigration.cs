namespace Halation.Core.Update;

/// <summary>
/// Carries saved settings from a previous product name's folder into the current one.
/// </summary>
/// <remarks>
/// <para>
/// The application was called VibeCheck until 0.1.4-beta, and its settings lived in a folder of
/// that name. Renaming the folder without moving anything would silently orphan every setting: an
/// API key the reader may no longer have, an endpoint they configured by hand, and an audience
/// choice whose <b>absence is meaningful</b> and would put the first-run question back in front of
/// somebody who has already answered it.
/// </para>
/// <para>
/// <b>Copies, never moves.</b> Nothing is deleted and the source folder is not written to at all,
/// not even a marker. Three reasons: reinstalling the older build still finds its own settings, a
/// copy cannot half-fail the way a move can, and a tool that raises findings about software
/// quietly deleting files in a user profile should not do it on first run.
/// </para>
/// <para>
/// The DPAPI-protected files travel as bytes and still decrypt, because
/// <c>DataProtectionScope.CurrentUser</c> binds the ciphertext to the Windows account rather than
/// to a path. That is the property the whole migration rests on, and it is the one thing here
/// tests cannot prove: <c>ProtectedData</c> is Windows-only and this project is not.
/// </para>
/// </remarks>
public static class SettingsMigration
{
    /// <summary>
    /// The files worth carrying, named rather than enumerated.
    /// </summary>
    /// <remarks>
    /// An allowlist, deliberately. Enumerating the folder would turn first run into a general
    /// file-copy primitive driven by whatever else happens to be sitting in the old directory,
    /// which is a poor shape for a security tool. It also lets two files stay behind on purpose:
    /// <c>crash.log</c>, because it holds stack traces from a differently-named product and a bug
    /// report should not arrive full of them; and <c>theme.xaml</c>, left over from a loose-theme
    /// feature that no longer exists, so nothing would read it in the new folder either.
    /// </remarks>
    public static IReadOnlyList<string> Files { get; } =
    [
        "deep-pass.key",
        "deep-pass-endpoint",
        "audience",
        "updates",
        "window",
        "hardware.json",
    ];

    /// <summary>
    /// Copies any of <see cref="Files"/> that exist in <paramref name="from"/> and are not
    /// already in <paramref name="to"/>. Returns how many were carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Guarded per file rather than per directory. A directory-level check ("skip if the new
    /// folder exists") reads as simpler and is wrong here, because the crash handler writes into
    /// that same folder and creates it on the way, so one crash before this ran would disable the
    /// migration permanently. Per-file guarding also means a run interrupted halfway resumes on
    /// the next launch at no extra cost.
    /// </para>
    /// <para>
    /// Never throws. Every store this feeds already treats an unreadable file as "not set", and a
    /// failed copy should leave the reader re-entering one setting rather than facing a dialog
    /// before the window has even opened.
    /// </para>
    /// </remarks>
    public static int Carry(string? from, string? to)
    {
        if (string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(to))
        {
            return 0;
        }

        if (!Directory.Exists(from))
        {
            return 0;
        }

        // Copying a folder onto itself would be a no-op at best and a lost file at worst.
        if (string.Equals(
                System.IO.Path.GetFullPath(from),
                System.IO.Path.GetFullPath(to),
                StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        var carried = 0;

        foreach (var name in Files)
        {
            var source = System.IO.Path.Combine(from, name);
            var destination = System.IO.Path.Combine(to, name);

            // Anything already saved under the new name wins. This is what makes a second run
            // harmless and stops a stale copy clobbering a setting changed since.
            if (File.Exists(destination) || !File.Exists(source))
            {
                continue;
            }

            try
            {
                // Created lazily, so a machine with nothing to carry does not get an empty
                // folder it never asked for.
                Directory.CreateDirectory(to);
                File.Copy(source, destination, overwrite: false);
                carried++;
            }
            catch (IOException)
            {
                // Locked, or gone between the check and the copy. The next launch tries again.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return carried;
    }
}
