using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

using Halation.Core.Model;

namespace Halation.App;

/// <summary>
/// Draws the scorecard image.
/// </summary>
/// <remarks>
/// <para>
/// 1200 by 630, which is the size link previews expect, so the same file works pasted into a
/// readme and shared as a card.
/// </para>
/// <para>
/// The layout is fixed rather than clever on purpose. This image is the one thing the product
/// produces that is meant to be looked at out of context, by somebody who has not run the tool,
/// and every fact on it is there to stop it being read as more than it is. The score is never
/// alone: the band that says what it means, the coverage that says how much was read, and the
/// hash that lets somebody check it are all the same size family as each other.
/// </para>
/// </remarks>
public static class ScorecardImage
{
    private const int Width = 1200;
    private const int Height = 630;

    public static void Save(Scorecard card, string path)
    {
        ArgumentNullException.ThrowIfNull(card);

        var bitmap = new RenderTargetBitmap(Width, Height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(Draw(card));

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));

        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static Brush Res(string key) => (Brush)Application.Current.Resources[key];

    private static FontFamily Face(string key) => (FontFamily)Application.Current.Resources[key];

    private static DrawingVisual Draw(Scorecard card)
    {
        var visual = new DrawingVisual();
        using var d = visual.RenderOpen();

        var bg = Res("Bg");
        var text = Res("Text");
        var muted = Res("Muted");
        var accent = Res("Accent");
        var edge = Res("Edge");

        d.DrawRectangle(bg, null, new Rect(0, 0, Width, Height));

        // The bleed the product is named for, along the bottom edge.
        d.DrawRectangle(accent, null, new Rect(0, Height - 7, Width, 7));

        var display = Face("DisplayFont");
        var ui = Face("UiFont");
        var mono = Face("MonoFont");

        // ---- the mark and the wordmark -------------------------------------
        try
        {
            var icon = new BitmapImage(
                new Uri("pack://application:,,,/Halation;component/Halation.ico"));
            d.DrawImage(icon, new Rect(64, 56, 46, 46));
        }
        catch (IOException)
        {
            // An image is not worth failing an export over.
        }

        Write(d, "HALATION", display, 30, FontWeights.Bold, accent, 124, 60);
        Write(d, "security scanner for AI-generated apps", ui, 17, FontWeights.Normal, muted, 124, 92);

        // ---- what was scanned ----------------------------------------------
        Write(d, Trim(card.ArtifactName, 42), display, 40, FontWeights.SemiBold, text, 64, 168);

        // ---- the score, and what it means ----------------------------------
        Write(d, card.ScoreDisplay, display, 96, FontWeights.Bold, ScoreBrush(card), 64, 236);
        Write(d, card.Band, ui, 27, FontWeights.SemiBold, ScoreBrush(card), 64, 356);

        // Coverage sits beside the score at the same weight rather than below it in small print.
        // A number without it is the misreading this whole card exists to prevent.
        Write(d, $"{card.CoveragePercent}% of the application could be read",
            ui, 19, FontWeights.Normal, muted, 64, 398);

        // ---- findings ------------------------------------------------------
        var x = 700.0;
        Write(d, "FINDINGS", ui, 15, FontWeights.SemiBold, muted, x, 178);

        var rows = new (string Label, int Count, string Key)[]
        {
            ("Critical", card.Critical, "Critical"),
            ("High", card.High, "High"),
            ("Medium", card.Medium, "Medium"),
            ("Low", card.Low, "Low"),
        };

        var y = 214.0;
        foreach (var (label, count, key) in rows)
        {
            var brush = count > 0 ? Res(key) : muted;
            d.DrawRectangle(brush, null, new Rect(x, y + 7, 4, 22));
            Write(d, label, ui, 20, FontWeights.Normal, count > 0 ? text : muted, x + 18, y);
            Write(d, count.ToString(CultureInfo.InvariantCulture), display, 22,
                FontWeights.SemiBold, brush, x + 132, y - 1);
            y += 38;
        }

        if (card.Info > 0)
        {
            Write(d, $"and {card.Info} not counted against the score",
                ui, 15, FontWeights.Normal, muted, x + 18, y + 4);
        }

        // ---- how to check it -----------------------------------------------
        d.DrawRectangle(edge, null, new Rect(64, 470, Width - 128, 1));

        Write(d, card.VerificationLine, ui, 16, FontWeights.Normal, muted, 64, 492);

        if (!string.IsNullOrEmpty(card.Sha256))
        {
            Write(d, $"SHA-256  {card.Sha256}", mono, 14, FontWeights.Normal, muted, 64, 522);
        }

        Write(d, card.ScannedAt.ToString("d MMMM yyyy", CultureInfo.InvariantCulture),
            ui, 16, FontWeights.Normal, muted, 64, 556);

        // Said out loud, because a badge that does not say this invites being read as one.
        Write(d, "Halation cannot say an application is safe, and does not claim to.",
            ui, 15, FontWeights.Normal, muted, 64, 582);

        return visual;
    }

    /// <summary>The score takes the colour of the band, so the number and its meaning agree.</summary>
    private static Brush ScoreBrush(Scorecard card) => card.Score switch
    {
        null => Res("Unknown"),
        < 40 => Res("Critical"),
        < 70 => Res("High"),
        < 90 => Res("Medium"),
        _ => Res("Good"),
    };

    private static string Trim(string value, int max) =>
        value.Length <= max ? value : value[..(max - 1)] + "…";

    private static void Write(
        DrawingContext d,
        string value,
        FontFamily family,
        double size,
        FontWeight weight,
        Brush brush,
        double x,
        double y)
    {
        var formatted = new FormattedText(
            value,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface(family, FontStyles.Normal, weight, FontStretches.Normal),
            size,
            brush,
            pixelsPerDip: 1.0);

        d.DrawText(formatted, new Point(x, y));
    }
}
