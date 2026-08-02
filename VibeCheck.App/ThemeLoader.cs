using System.IO;
using System.Windows;
using System.Windows.Markup;

namespace VibeCheck.App;

/// <summary>
/// Merges an optional user theme over the built-in one.
/// </summary>
/// <remarks>
/// <para>
/// The default theme is compiled into the application, so it is always present and always
/// works. This looks for a loose <c>theme.xaml</c> beside it in the user's data folder and,
/// when one exists, merges it last so its keys win. An override therefore only needs to
/// contain what it changes, and reverting is deleting a file rather than reinstalling.
/// </para>
/// <para>
/// A theme that fails to parse is reported and skipped, never fatal. Somebody experimenting
/// with colours should get their application back with a message about the mistake, not a
/// window that refuses to open and no way to find out why.
/// </para>
/// </remarks>
public static class ThemeLoader
{
    /// <summary>Where a user theme is read from, whether or not one is there.</summary>
    public static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VibeCheck",
        "theme.xaml");

    /// <summary>
    /// Applies the user theme if there is one. Returns the problem when there was a theme
    /// and it could not be used, and null when there was nothing to do or it worked.
    /// </summary>
    public static string? Apply(Application application)
    {
        ArgumentNullException.ThrowIfNull(application);

        if (!File.Exists(Path))
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(Path);

            if (XamlReader.Load(stream) is not ResourceDictionary theme)
            {
                return $"{Path} is valid XAML but is not a ResourceDictionary, so it was ignored.";
            }

            // Appended rather than inserted: later dictionaries win on duplicate keys, which
            // is what makes a partial override work.
            application.Resources.MergedDictionaries.Add(theme);
            return null;
        }
        catch (IOException ex)
        {
            return $"{Path} could not be opened and was ignored.\n\n{ex.Message}";
        }
        catch (UnauthorizedAccessException ex)
        {
            return $"{Path} could not be opened and was ignored.\n\n{ex.Message}";
        }

        // Deliberately broad, and the one place in this codebase where that is the right
        // shape. This parses a hand-edited file of arbitrary content, and the exceptions
        // XamlReader can raise for arbitrary input are not enumerable: XamlParseException for
        // XAML-level mistakes, XmlException for XML-level ones such as a "--" inside a
        // comment, and type converter exceptions for anything a value fails to become.
        // Catching only the ones that came to mind is how "a bad edit cannot stop the
        // application starting" quietly stopped being true, which is what happened here: an
        // illegal comment took the whole window down and only the catch list was at fault.
        catch (Exception ex)
        {
            return $"{Path} could not be read as a theme and was ignored.\n\n{ex.Message}";
        }
    }
}
