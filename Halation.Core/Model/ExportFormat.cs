namespace Halation.Core.Model;

/// <summary>
/// The ways a finished report can be taken away.
/// </summary>
public enum ExportFormat
{
    /// <summary>The full report as Markdown, quoted code and all.</summary>
    Markdown,

    /// <summary>Every field, structured, for something else to read.</summary>
    Json,

    /// <summary>Markdown with the reader's own code taken out, so it can be published.</summary>
    Sharing,

    /// <summary>An image of the result, for showing rather than reading.</summary>
    Scorecard,
}

/// <summary>
/// What each export is, in the words the reader is shown when choosing between them.
/// </summary>
/// <remarks>
/// The copy lives here rather than in the window for the same reason
/// <see cref="ApplicationKinds"/> does: it is the answer to a question the product has an
/// opinion about, it has to agree with what the documentation says, and a test can check it is
/// present for every member of the enum. A new format cannot be added without wording it.
/// </remarks>
public static class ExportFormats
{
    public static IReadOnlyList<ExportFormat> All { get; } = Enum.GetValues<ExportFormat>();

    /// <summary>The name on the option.</summary>
    public static string Label(this ExportFormat format) => format switch
    {
        ExportFormat.Markdown => "Markdown",
        ExportFormat.Json => "JSON",
        ExportFormat.Sharing => "Markdown for sharing",
        ExportFormat.Scorecard => "Scorecard image",
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <summary>What it is for, and what is in it.</summary>
    public static string Description(this ExportFormat format) => format switch
    {
        ExportFormat.Markdown =>
            "The whole report, for reading and keeping. Every finding quotes the line of code it "
            + "was found in and names the file, which is what lets you check a claim rather than "
            + "believe it. That also makes it a document full of your own source.",

        ExportFormat.Json =>
            "Every field, structured, with a version number, for feeding to something else. It "
            + "contains the same quoted code the Markdown does.",

        ExportFormat.Sharing =>
            "The same report with the quoted code, file names and hash removed, so it can be "
            + "posted in public or sent to somebody who should not see the source. The findings "
            + "and the score are unchanged.",

        ExportFormat.Scorecard =>
            "An image of the result to attach to a readme or a post. Carries the score, how much "
            + "of the application could be read, what was found, and the hash of the file that "
            + "was scanned, so anyone can rescan the same file and check they get the same "
            + "answer.",

        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <summary>Whether the file carries the reader's own source.</summary>
    /// <remarks>
    /// The one fact worth surfacing on its own rather than leaving inside the sentence above.
    /// It is the only difference that matters once a file has left the machine.
    /// </remarks>
    public static bool CarriesYourCode(this ExportFormat format) => format switch
    {
        ExportFormat.Markdown or ExportFormat.Json => true,
        ExportFormat.Sharing or ExportFormat.Scorecard => false,
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    public static string Extension(this ExportFormat format) => format switch
    {
        ExportFormat.Markdown or ExportFormat.Sharing => "md",
        ExportFormat.Json => "json",
        ExportFormat.Scorecard => "png",
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    public static string FileFilter(this ExportFormat format) => format switch
    {
        ExportFormat.Markdown or ExportFormat.Sharing => "Markdown (*.md)|*.md",
        ExportFormat.Json => "JSON (*.json)|*.json",
        ExportFormat.Scorecard => "PNG image (*.png)|*.png",
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <summary>
    /// The suffix on the suggested file name, so the two Markdown files are not confused.
    /// </summary>
    /// <remarks>
    /// Only one of them is safe to attach to anything, and they are otherwise the same shape
    /// with the same extension.
    /// </remarks>
    public static string FileSuffix(this ExportFormat format) => format switch
    {
        ExportFormat.Sharing => "-halation-shared",
        ExportFormat.Scorecard => "-halation-scorecard",
        _ => "-halation",
    };
}
