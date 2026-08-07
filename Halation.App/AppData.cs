namespace Halation.App;

/// <summary>
/// Where this application keeps what it remembers between runs.
/// </summary>
/// <remarks>
/// <para>
/// One place, because the folder name used to be repeated as a bare string in seven files and a
/// rename had to find all seven. Nothing here is secret; the two files that need protecting are
/// encrypted by the stores that own them.
/// </para>
/// <para>
/// The accessor is called <see cref="PathTo"/> rather than <c>Path</c> or <c>File</c> on purpose:
/// every store in this project already writes <c>System.IO.Path.Combine</c> in full to work around
/// its own shadowing property, and adding another name to trip over would not help.
/// </para>
/// </remarks>
internal static class AppData
{
    internal const string FolderName = "Halation";

    /// <summary>The folder this application used before it was renamed, in 0.1.4-beta.</summary>
    internal const string LegacyFolderName = "VibeCheck";

    internal static string Directory => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        FolderName);

    internal static string LegacyDirectory => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        LegacyFolderName);

    internal static string PathTo(string fileName) =>
        System.IO.Path.Combine(Directory, fileName);
}
