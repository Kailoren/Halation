using System.IO;

namespace Halation.Core;

/// <summary>What to put on the progress bar and beside it, at one moment.</summary>
public readonly record struct PacedProgress(int Percent, string Message);

/// <summary>
/// How long the progress readout runs, and how big the artifact is that decides it.
/// </summary>
/// <remarks>
/// <para>
/// A scan of a typical application finishes in under two seconds, and in testing nobody
/// believed it. The receipt on the results screen says exactly what was examined, and it turns
/// out that a reader who watched the bar flash past does not go looking for it: they have
/// already decided nothing happened.
/// </para>
/// <para>
/// <b>This slows the readout, never the scan.</b> The work runs at full speed and the report
/// records the time it really took. What is stretched is the reporting of it, so that stages
/// which genuinely ran are on screen long enough to be read. See <see cref="ScanPacer"/> for
/// the rule that keeps the bar honest while it does that.
/// </para>
/// </remarks>
public static class ScanPacing
{
    /// <summary>The floor, for something small enough to be scanned almost instantly.</summary>
    public static TimeSpan Shortest { get; } = TimeSpan.FromSeconds(5);

    /// <summary>The ceiling. Past a certain size, longer stops reading as thorough.</summary>
    public static TimeSpan Longest { get; } = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Files counted before the measurement gives up and answers with what it has.
    /// </summary>
    /// <remarks>
    /// This runs before the scan starts, so it is time added to every scan and has to stay
    /// small. It only decides how long a bar runs for, and a source tree with more than this
    /// many files is already past the point where the answer changes.
    /// </remarks>
    private const int MaxFilesMeasured = 20_000;

    /// <summary>
    /// How long the readout should run for an artifact of this size.
    /// </summary>
    /// <remarks>
    /// Logarithmic rather than linear, because size spans four orders of magnitude here: a
    /// source folder is a few megabytes and an Electron installer is a few hundred, and a
    /// linear scale would give the first of those no time at all and the second all of it.
    /// </remarks>
    public static TimeSpan TargetFor(long bytes)
    {
        var megabytes = Math.Max(1, bytes / (1024d * 1024));
        var seconds = 5 + (4.3 * Math.Log10(megabytes));

        return TimeSpan.FromSeconds(
            Math.Clamp(seconds, Shortest.TotalSeconds, Longest.TotalSeconds));
    }

    /// <summary>
    /// Roughly how much there is, for the purpose above and no other.
    /// </summary>
    /// <remarks>
    /// Bounded and forgiving: an unreadable file or a folder that cannot be entered answers
    /// zero rather than throwing, because nothing here is worth failing a scan over.
    /// </remarks>
    public static long Measure(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return 0;
        }

        try
        {
            if (File.Exists(path))
            {
                return new FileInfo(path).Length;
            }

            if (!Directory.Exists(path))
            {
                return 0;
            }

            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
            };

            long total = 0;
            var counted = 0;

            foreach (var file in Directory.EnumerateFiles(path, "*", options))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch (IOException)
                {
                }

                if (++counted >= MaxFilesMeasured)
                {
                    break;
                }
            }

            return total;
        }
        catch (IOException)
        {
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return 0;
        }
    }

    /// <summary>
    /// Where a stage sits in the scan as a whole.
    /// </summary>
    /// <remarks>
    /// Each stage reports progress through its own work, so "50%" means half of the rule pass
    /// rather than half of the scan. Without this the bar filled during the rule pass and then
    /// sat at 100% through the dependency check, the deep pass and scoring, which is the
    /// opposite of the problem this file exists to solve.
    /// </remarks>
    public static int Overall(ScanProgress report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var (start, end) = BandFor(report.Stage);
        var within = Math.Clamp(report.Percent ?? 0, 0, 100) / 100d;

        return (int)Math.Round(start + ((end - start) * within));
    }

    /// <summary>
    /// Where a stage begins, which is the point its message becomes true.
    /// </summary>
    /// <remarks>
    /// A stage's label is owed to the reader as soon as the bar enters its band, not at
    /// whatever position that stage first happened to report from. The rule pass announces
    /// itself at 0% of its own work and the deep pass at its first file, so in practice the two
    /// agree; where they do not, the stage having started is the true statement and the
    /// previous stage still being under way is the false one.
    /// </remarks>
    public static int StartOf(ScanStage stage) => BandFor(stage).Start;

    private static (int Start, int End) BandFor(ScanStage stage) => stage switch
    {
        ScanStage.Identifying => (0, 4),
        ScanStage.Recovering => (4, 28),
        ScanStage.Analysing => (28, 64),
        ScanStage.CheckingDependencies => (64, 72),

        // The widest band, because when it runs at all it is most of the wait.
        ScanStage.DeepPass => (72, 96),
        ScanStage.Scoring => (96, 99),
        _ => (100, 100),
    };
}

/// <summary>
/// Decides what the progress bar shows, given how long the scan has been running.
/// </summary>
/// <remarks>
/// <para>
/// Two numbers meet here. One is how far through the scan really is, which arrives from the
/// scanner. The other is how far through the readout should be by now, which is time elapsed
/// against <see cref="ScanPacing.TargetFor"/>. <b>The bar shows the lower of the two</b>, and
/// that single rule is what separates this from a fake progress bar:
/// </para>
/// <list type="bullet">
/// <item>It can never claim progress that has not happened, because the real figure caps it.</item>
/// <item>It can never finish before there has been time to read it, because the paced figure
/// caps it.</item>
/// <item>A scan that genuinely takes longer than the target is not slowed at all: the real
/// figure is the lower one throughout, and the bar simply tracks it.</item>
/// </list>
/// <para>
/// The message follows the bar rather than the scan, so each stage is on screen while the bar
/// is inside that stage's band. Every message shown is one the scanner really reported for
/// work it really did; the only thing this decides is which of them is on screen now.
/// </para>
/// </remarks>
public sealed class ScanPacer(TimeSpan target)
{
    /// <summary>
    /// Each distinct message and the point at which it <b>first</b> appeared.
    /// </summary>
    /// <remarks>
    /// First rather than latest, and the distinction is the whole behaviour of the readout. The
    /// rule pass reports the same sentence for every file it works through, from 28% to 64%; an
    /// entry holding the last of those would only be selected once the bar had left the stage,
    /// so the label for the longest part of the scan would appear as it ended and the previous
    /// stage's label would sit there throughout.
    /// </remarks>
    private readonly List<(int From, string Message)> _messages = [];

    private readonly Lock _gate = new();

    /// <summary>
    /// The furthest the scan has actually got. Tracked separately from the list above, which
    /// records where messages started rather than where the work has reached.
    /// </summary>
    private int _furthest;

    public TimeSpan Target { get; } = target;

    /// <summary>Takes a report from the scanner. Nothing is displayed until it is sampled.</summary>
    public void Record(ScanProgress report)
    {
        ArgumentNullException.ThrowIfNull(report);

        lock (_gate)
        {
            // Never backwards. The deep pass and the rule pass both count through their own
            // files, so a bar following them literally would rewind between stages.
            _furthest = Math.Max(_furthest, ScanPacing.Overall(report));

            // Only a change of message is worth an entry, so a twenty-thousand-file scan does
            // not keep twenty thousand copies of one sentence to choose between.
            if (_messages.Count > 0
                && string.Equals(_messages[^1].Message, report.Message, StringComparison.Ordinal))
            {
                return;
            }

            // Where the stage begins rather than where it currently is, so the label is on
            // screen for the whole band it describes. Held at or after the previous message's
            // point, since the list is walked in order.
            var from = ScanPacing.StartOf(report.Stage);

            if (_messages.Count > 0)
            {
                from = Math.Max(from, _messages[^1].From);
            }

            _messages.Add((from, report.Message));
        }
    }

    /// <summary>What to show after this much time. Pure: the same inputs always answer the same.</summary>
    public PacedProgress Sample(TimeSpan elapsed)
    {
        var paced = Target > TimeSpan.Zero
            ? (int)(100 * elapsed.TotalSeconds / Target.TotalSeconds)
            : 100;

        paced = Math.Clamp(paced, 0, 100);

        lock (_gate)
        {
            if (_messages.Count == 0)
            {
                return new PacedProgress(0, string.Empty);
            }

            // The rule this class exists for: the lower of what has happened and what there has
            // been time to read.
            var shown = Math.Min(paced, _furthest);
            var message = _messages[0].Message;

            foreach (var entry in _messages)
            {
                if (entry.From <= shown)
                {
                    message = entry.Message;
                }
            }

            return new PacedProgress(shown, message);
        }
    }

    /// <summary>Whether the readout has had its time, which is separate from the scan finishing.</summary>
    public bool Finished(TimeSpan elapsed) => elapsed >= Target;
}
