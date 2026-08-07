using Halation.Core;

namespace Halation.Tests;

/// <summary>
/// The paced progress readout.
/// </summary>
/// <remarks>
/// This is the one place in the application where the interface deliberately takes longer than
/// the work, so it is the one place where a claim could be made that is not true. The property
/// worth protecting is that it never reports progress the scanner has not reported first.
/// </remarks>
public class ScanPacingTests : IDisposable
{
    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), $"halation-pacing-{Guid.NewGuid():N}");

    public ScanPacingTests() => Directory.CreateDirectory(_scratch);

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private static ScanProgress At(ScanStage stage, int? percent = null, string message = "working") =>
        new(stage, message, percent);

    // ---- How long it runs for -----------------------------------------------

    [Fact]
    public void SomethingTinyStillGetsTheFloor()
    {
        Assert.Equal(ScanPacing.Shortest, ScanPacing.TargetFor(0));
        Assert.Equal(ScanPacing.Shortest, ScanPacing.TargetFor(64 * 1024));
    }

    [Fact]
    public void NothingRunsPastTheCeiling() =>
        Assert.Equal(ScanPacing.Longest, ScanPacing.TargetFor(500L * 1024 * 1024 * 1024));

    [Fact]
    public void BiggerTakesLonger()
    {
        var small = ScanPacing.TargetFor(5L * 1024 * 1024);
        var release = ScanPacing.TargetFor(66L * 1024 * 1024);
        var installer = ScanPacing.TargetFor(400L * 1024 * 1024);

        Assert.True(small < release);
        Assert.True(release < installer);

        // A release-sized application should land in the middle of the range rather than at
        // either end, which is the case the scale was chosen for.
        Assert.InRange(release.TotalSeconds, 10, 15);
    }

    [Fact]
    public void EveryDurationIsInsideTheStatedRange()
    {
        foreach (var megabytes in new[] { 0, 1, 10, 100, 1_000, 100_000 })
        {
            var target = ScanPacing.TargetFor(megabytes * 1024L * 1024);

            Assert.InRange(target, ScanPacing.Shortest, ScanPacing.Longest);
        }
    }

    // ---- Measuring the artifact ---------------------------------------------

    [Fact]
    public void MeasuresAFile()
    {
        var path = Path.Combine(_scratch, "app.exe");
        File.WriteAllBytes(path, new byte[4096]);

        Assert.Equal(4096, ScanPacing.Measure(path));
    }

    [Fact]
    public void MeasuresAFolderIncludingItsSubfolders()
    {
        Directory.CreateDirectory(Path.Combine(_scratch, "resources"));
        File.WriteAllBytes(Path.Combine(_scratch, "app.exe"), new byte[1000]);
        File.WriteAllBytes(Path.Combine(_scratch, "resources", "app.asar"), new byte[2000]);

        Assert.Equal(3000, ScanPacing.Measure(_scratch));
    }

    /// <summary>Nothing here is worth failing a scan over, so a bad path answers zero.</summary>
    [Fact]
    public void MeasuringSurvivesWhatIsNotThere()
    {
        Assert.Equal(0, ScanPacing.Measure(null));
        Assert.Equal(0, ScanPacing.Measure("   "));
        Assert.Equal(0, ScanPacing.Measure(Path.Combine(_scratch, "gone")));
    }

    // ---- Where each stage sits in the whole ---------------------------------

    /// <summary>
    /// Each stage counts through its own work, so without this the bar filled during the rule
    /// pass and then sat at 100% for everything after it.
    /// </summary>
    [Fact]
    public void StagesRunForwardsThroughTheScan()
    {
        var order = new[]
        {
            ScanPacing.Overall(At(ScanStage.Identifying)),
            ScanPacing.Overall(At(ScanStage.Recovering)),
            ScanPacing.Overall(At(ScanStage.Analysing)),
            ScanPacing.Overall(At(ScanStage.CheckingDependencies)),
            ScanPacing.Overall(At(ScanStage.DeepPass)),
            ScanPacing.Overall(At(ScanStage.Scoring)),
            ScanPacing.Overall(At(ScanStage.Complete)),
        };

        Assert.Equal(order, order.OrderBy(p => p).ToArray());
        Assert.Equal(100, order[^1]);
    }

    [Fact]
    public void AStagesOwnProgressMovesWithinItsBand()
    {
        var start = ScanPacing.Overall(At(ScanStage.Analysing, 0));
        var middle = ScanPacing.Overall(At(ScanStage.Analysing, 50));
        var end = ScanPacing.Overall(At(ScanStage.Analysing, 100));

        Assert.True(start < middle);
        Assert.True(middle < end);

        // And never past the stage that follows it.
        Assert.True(end <= ScanPacing.Overall(At(ScanStage.CheckingDependencies)));
    }

    // ---- The rule that keeps it honest --------------------------------------

    /// <summary>
    /// The whole point. However long the readout is given, it cannot show progress the scanner
    /// has not reported.
    /// </summary>
    [Fact]
    public void NeverShowsMoreProgressThanHasHappened()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(10));

        pacer.Record(At(ScanStage.Recovering, message: "Recovering"));

        var recovering = ScanPacing.Overall(At(ScanStage.Recovering));

        // Nine seconds in, the paced figure would be 90%. The scan has reached the recovery
        // stage and no further, so that is what is shown.
        Assert.Equal(recovering, pacer.Sample(TimeSpan.FromSeconds(9)).Percent);
        Assert.Equal(recovering, pacer.Sample(TimeSpan.FromSeconds(60)).Percent);
    }

    /// <summary>And the other half: a finished scan does not slam the bar to the end.</summary>
    [Fact]
    public void DoesNotFinishBeforeItCanBeRead()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(10));

        pacer.Record(At(ScanStage.Complete, 100, "Scan complete"));

        Assert.Equal(0, pacer.Sample(TimeSpan.Zero).Percent);
        Assert.Equal(50, pacer.Sample(TimeSpan.FromSeconds(5)).Percent);
        Assert.Equal(100, pacer.Sample(TimeSpan.FromSeconds(10)).Percent);
        Assert.False(pacer.Finished(TimeSpan.FromSeconds(9)));
        Assert.True(pacer.Finished(TimeSpan.FromSeconds(10)));
    }

    /// <summary>A scan slower than the readout is not slowed further; the bar just follows it.</summary>
    [Fact]
    public void AddsNothingToAScanThatIsAlreadySlow()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(5));

        pacer.Record(At(ScanStage.DeepPass, 25, "Deep pass 1 of 4"));

        var atQuarter = ScanPacing.Overall(At(ScanStage.DeepPass, 25));

        // Well past the target, and still showing exactly where the scan has got to.
        Assert.Equal(atQuarter, pacer.Sample(TimeSpan.FromSeconds(30)).Percent);
    }

    [Fact]
    public void ShowsNothingBeforeTheScannerHasSaidAnything()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(10));

        var sample = pacer.Sample(TimeSpan.FromSeconds(3));

        Assert.Equal(0, sample.Percent);
        Assert.Equal(string.Empty, sample.Message);
    }

    // ---- Which message is on screen -----------------------------------------

    /// <summary>
    /// The messages arrive in a rush from a fast scan. They are shown one at a time as the bar
    /// reaches each one, which is what makes the wait worth anything.
    /// </summary>
    [Fact]
    public void RevealsEachStageAsTheBarReachesIt()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(10));

        pacer.Record(At(ScanStage.Identifying, message: "Identifying artifact"));
        pacer.Record(At(ScanStage.Recovering, message: "Recovering source"));
        pacer.Record(At(ScanStage.Analysing, 100, "Analysing 412 files"));
        pacer.Record(At(ScanStage.CheckingDependencies, message: "Checking dependencies"));
        pacer.Record(At(ScanStage.Complete, 100, "Scan complete"));

        Assert.Equal("Identifying artifact", pacer.Sample(TimeSpan.FromSeconds(0.1)).Message);
        Assert.Equal("Recovering source", pacer.Sample(TimeSpan.FromSeconds(1)).Message);
        Assert.Equal("Analysing 412 files", pacer.Sample(TimeSpan.FromSeconds(4)).Message);
        Assert.Equal("Checking dependencies", pacer.Sample(TimeSpan.FromSeconds(7)).Message);
        Assert.Equal("Scan complete", pacer.Sample(TimeSpan.FromSeconds(10)).Message);
    }

    /// <summary>
    /// The deep pass counts its own files from zero. Following that literally rewound the bar
    /// to the middle of the scan every time it started.
    /// </summary>
    [Fact]
    public void NeverRunsBackwards()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(1));

        pacer.Record(At(ScanStage.CheckingDependencies, message: "Checking dependencies"));
        pacer.Record(At(ScanStage.DeepPass, 0, "Deep pass 1 of 8"));

        var dependencies = ScanPacing.Overall(At(ScanStage.CheckingDependencies));

        Assert.True(pacer.Sample(TimeSpan.FromSeconds(1)).Percent >= dependencies);
    }

    /// <summary>
    /// The rule pass reports once per file with the same sentence every time. A twenty
    /// thousand file scan must not keep twenty thousand copies of it to choose between.
    /// </summary>
    [Fact]
    public void CollapsesRepeatsOfTheSameMessage()
    {
        var pacer = new ScanPacer(TimeSpan.FromSeconds(10));

        for (var done = 0; done <= 100; done++)
        {
            pacer.Record(At(ScanStage.Analysing, done, "Analysing 20,000 files"));
        }

        pacer.Record(At(ScanStage.Complete, 100, "Scan complete"));

        Assert.Equal("Analysing 20,000 files", pacer.Sample(TimeSpan.FromSeconds(5)).Message);
        Assert.Equal("Scan complete", pacer.Sample(TimeSpan.FromSeconds(10)).Message);
    }
}
