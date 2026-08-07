using VibeCheck.Core.Update;

namespace VibeCheck.Tests;

/// <summary>
/// Replacing the running application with a downloaded one.
/// </summary>
/// <remarks>
/// The failure to be afraid of here is not a bad update, it is no update: a swap that goes
/// wrong halfway leaves the machine with nothing under the name every shortcut points at.
/// </remarks>
public class UpdateInstallTests : IDisposable
{
    /// <summary>
    /// A copy installed from the Store is updated by the Store, and says so.
    /// </summary>
    /// <remarks>
    /// Checked before every other refusal because the other two both fire on a packaged build
    /// and both say something untrue. Observed on a real package built from this project: the
    /// install directory is read-only, so the writability probe reports a permissions fault,
    /// and the package ships its <c>.deps.json</c>, so the development-build check calls a
    /// Store installation somebody's working copy. That message won, being first.
    /// </remarks>
    [Fact]
    public void A_packaged_copy_refuses_and_says_the_store_handles_it()
    {
        var capability = UpdateInstall.Assess(
            Environment.ProcessPath, packaged: true);

        Assert.False(capability.CanInstall);
        Assert.Contains("Microsoft Store", capability.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("development build", capability.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cannot write", capability.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And the test process is not packaged, so the default answer must not be the packaged
    /// one. Without this the check above would pass against a constant.
    /// </summary>
    [Fact]
    public void An_ordinary_build_is_not_detected_as_packaged()
    {
        Assert.False(PackageIdentity.IsPackaged);

        Assert.DoesNotContain(
            "Microsoft Store",
            UpdateInstall.Assess(Environment.ProcessPath).Detail,
            StringComparison.Ordinal);
    }

    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), $"vibecheck-update-{Guid.NewGuid():N}");

    public UpdateInstallTests() => Directory.CreateDirectory(_scratch);

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private string Write(string name, string content)
    {
        var path = Path.Combine(_scratch, name);
        File.WriteAllText(path, content);

        return path;
    }

    // ---- Whether this copy may install at all -------------------------------

    [Fact]
    public void RefusesWhenTheRunningFileCannotBeFound()
    {
        Assert.False(UpdateInstall.Assess(null).CanInstall);
        Assert.False(UpdateInstall.Assess(Path.Combine(_scratch, "nothing.exe")).CanInstall);
    }

    /// <summary>
    /// A build output is not an installation. Replacing one with a released single file would
    /// delete somebody's working directory in exchange for an application that no longer
    /// matches the source next to it.
    /// </summary>
    [Fact]
    public void RefusesADevelopmentBuild()
    {
        var exe = Write("Halation.exe", "not really");
        Write("Halation.deps.json", "{}");

        var capability = UpdateInstall.Assess(exe);

        Assert.False(capability.CanInstall);
        Assert.Contains("development build", capability.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The state every reader is in today: nothing is signed, so there is no publisher a
    /// download could be held to, so nothing is installed. The refusal names itself rather than
    /// hiding the button.
    /// </summary>
    [Fact]
    public void RefusesWhenThereIsNoPublisherToMatch()
    {
        var exe = Write("Halation.exe", "not really an executable");

        var capability = UpdateInstall.Assess(exe);

        Assert.False(capability.CanInstall);
        Assert.Null(capability.ExpectedPublisher);
        Assert.Contains("code-signed", capability.Detail, StringComparison.OrdinalIgnoreCase);

        // Still knows what it would have replaced, which is what the sweep needs.
        Assert.Equal(exe, capability.TargetPath);
    }

    /// <summary>A download is refused for the same reason, rather than slipping past.</summary>
    [Fact]
    public void RefusesToInstallWhatItCannotVerify()
    {
        var exe = Write("Halation.exe", "not really an executable");
        var download = Write("Halation.exe.0.2.0.download", "also not an executable");

        Assert.NotNull(UpdateInstall.Reject(download, UpdateInstall.Assess(exe)));
    }

    /// <summary>
    /// An unsigned download is refused even when the capability says otherwise, because the
    /// signature check is the gate rather than the button that leads to it.
    /// </summary>
    [Fact]
    public void RefusesAnUnsignedDownloadOutright()
    {
        var download = Write("candidate.exe", "not signed by anyone");

        var pretend = new InstallCapability
        {
            CanInstall = true,
            TargetPath = Path.Combine(_scratch, "Halation.exe"),
            ExpectedPublisher = "CN=Somebody",
            Detail = "pretend",
        };

        var refusal = UpdateInstall.Reject(download, pretend);

        Assert.NotNull(refusal);
        Assert.Contains("not code-signed", refusal, StringComparison.OrdinalIgnoreCase);
    }

    // ---- The swap ----------------------------------------------------------

    [Fact]
    public void PutsTheNewBuildInPlaceAndKeepsTheOldOne()
    {
        var target = Write("Halation.exe", "old build");
        var staged = Write("Halation.exe.0.2.0.download", "new build");

        UpdateInstall.Replace(staged, target);

        Assert.Equal("new build", File.ReadAllText(target));
        Assert.Equal("old build", File.ReadAllText(target + UpdateInstall.SupersededSuffix));
        Assert.False(File.Exists(staged));
    }

    /// <summary>
    /// The case that matters. If the second move fails, the first one has already renamed the
    /// only working copy out of the way.
    /// </summary>
    [Fact]
    public void PutsTheOldBuildBackWhenTheNewOneCannotBeMoved()
    {
        var target = Write("Halation.exe", "old build");
        var missing = Path.Combine(_scratch, "never-downloaded.exe");

        Assert.ThrowsAny<IOException>(() => UpdateInstall.Replace(missing, target));

        Assert.True(File.Exists(target));
        Assert.Equal("old build", File.ReadAllText(target));
        Assert.False(File.Exists(target + UpdateInstall.SupersededSuffix));
    }

    /// <summary>Two updates in one session must not trip over the first one's leftovers.</summary>
    [Fact]
    public void MakesRoomForASecondUpdate()
    {
        var target = Write("Halation.exe", "first");
        Write("Halation.exe" + UpdateInstall.SupersededSuffix, "already there");
        var staged = Write("Halation.exe.0.3.0.download", "second");

        UpdateInstall.Replace(staged, target);

        Assert.Equal("second", File.ReadAllText(target));
        Assert.Equal("first", File.ReadAllText(target + UpdateInstall.SupersededSuffix));
    }

    // ---- Clearing up -------------------------------------------------------

    /// <summary>
    /// This deletes files in a folder somebody else chose, so it matches by exact name rather
    /// than by wildcard.
    /// </summary>
    [Fact]
    public void SweepsOnlyItsOwnLeftovers()
    {
        var target = Write("Halation.exe", "current");
        Write("Halation.exe" + UpdateInstall.SupersededSuffix, "previous");
        Write("Halation.exe.superseded-abc123", "the one before that");
        Write("Halation.exe.0.2.0.download", "half a download");

        var keep = new[]
        {
            Write("notes.download", "somebody else's file"),
            Write("HalationReport.md", "a report"),
            Write("Halation.exe.config", "configuration"),
        };

        var removed = UpdateInstall.SweepSuperseded(target);

        Assert.Equal(3, removed);
        Assert.True(File.Exists(target));

        foreach (var file in keep)
        {
            Assert.True(File.Exists(file), $"{Path.GetFileName(file)} should have been left alone");
        }
    }

    [Fact]
    public void SweepingSurvivesAMissingFolder()
    {
        Assert.Equal(0, UpdateInstall.SweepSuperseded(null));
        Assert.Equal(0, UpdateInstall.SweepSuperseded(Path.Combine(_scratch, "gone", "Halation.exe")));
    }
}
