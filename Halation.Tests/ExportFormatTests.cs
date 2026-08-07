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
}
