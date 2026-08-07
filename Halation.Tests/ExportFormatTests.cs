using Halation.Core.Model;

namespace Halation.Tests;

/// <summary>
/// Covers the copy the export chooser shows, which is the only place a reader is told which of
/// these files carries their own source.
/// </summary>
public sealed class ExportFormatTests
{
    public static TheoryData<ExportFormat> Every()
    {
        var data = new TheoryData<ExportFormat>();
        foreach (var format in ExportFormats.All)
        {
            data.Add(format);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Every))]
    public void EveryFormatIsWorded(ExportFormat format)
    {
        Assert.False(string.IsNullOrWhiteSpace(format.Label()));
        Assert.False(string.IsNullOrWhiteSpace(format.Extension()));
        Assert.False(string.IsNullOrWhiteSpace(format.FileFilter()));
        Assert.False(string.IsNullOrWhiteSpace(format.FileSuffix()));

        // Long enough to actually say what the file is, since that is the entire reason the
        // chooser exists rather than four buttons.
        Assert.True(format.Description().Length > 60, $"{format} needs a real description");
    }

    [Fact]
    public void AllCoversTheWholeEnum() =>
        Assert.Equal(Enum.GetValues<ExportFormat>().Length, ExportFormats.All.Count);

    [Fact]
    public void LabelsAreDistinct() =>
        Assert.Equal(
            ExportFormats.All.Count,
            ExportFormats.All.Select(f => f.Label()).Distinct(StringComparer.Ordinal).Count());

    [Fact]
    public void OnlyTheFullReportsCarryTheReadersCode()
    {
        Assert.True(ExportFormat.Markdown.CarriesYourCode());
        Assert.True(ExportFormat.Json.CarriesYourCode());
        Assert.False(ExportFormat.Sharing.CarriesYourCode());
        Assert.False(ExportFormat.Scorecard.CarriesYourCode());
    }

    /// <summary>
    /// The two Markdown exports share an extension, so the suggested file name is the only thing
    /// telling them apart on disk, and only one of them can be attached to anything.
    /// </summary>
    [Fact]
    public void TheTwoMarkdownFilesAreNamedDifferently()
    {
        Assert.Equal("md", ExportFormat.Markdown.Extension());
        Assert.Equal("md", ExportFormat.Sharing.Extension());
        Assert.NotEqual(ExportFormat.Markdown.FileSuffix(), ExportFormat.Sharing.FileSuffix());
    }

    [Fact]
    public void ExtensionsMatchTheFormat()
    {
        Assert.Equal("json", ExportFormat.Json.Extension());
        Assert.Equal("png", ExportFormat.Scorecard.Extension());
    }

    /// <summary>
    /// The chooser must not promise a hash the card will not carry.
    /// </summary>
    /// <remarks>
    /// <see cref="Scorecard.Sha256"/> is deliberately empty for a directory scan, because the
    /// scanner's value there describes file names and sizes rather than code. Copy that offers
    /// the hash unconditionally sells a verification the image then declines to support, which
    /// is the overclaim the card was changed to avoid. It shipped once; this pins it.
    /// </remarks>
    [Fact]
    public void TheScorecardDescriptionDoesNotPromiseAHashForEveryScan()
    {
        var description = ExportFormat.Scorecard.Description();

        Assert.Contains("hash", description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("folder", description, StringComparison.OrdinalIgnoreCase);

        // The claim has to be attached to scanning a file, not to the format in general.
        var hash = description.IndexOf("hash", StringComparison.OrdinalIgnoreCase);
        var file = description.IndexOf("file", StringComparison.OrdinalIgnoreCase);
        Assert.InRange(file, 0, hash);
    }
}
