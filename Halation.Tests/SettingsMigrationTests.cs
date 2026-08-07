using Halation.Core.Update;

namespace Halation.Tests;

/// <summary>
/// Covers carrying settings out of the folder the application used before it was renamed.
/// </summary>
/// <remarks>
/// The one property these cannot check is the one the migration rests on: that a DPAPI blob
/// still decrypts after being copied, because it is bound to the Windows account rather than to
/// a path. <c>ProtectedData</c> is Windows-only and this project is not, so that is verified by
/// hand against a real profile instead.
/// </remarks>
public sealed class SettingsMigrationTests : IDisposable
{
    private readonly string _scratch =
        Directory.CreateTempSubdirectory("halation-migration-").FullName;

    private string From => Path.Combine(_scratch, "old");

    private string To => Path.Combine(_scratch, "new");

    private string Write(string directory, string name, string content)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void CarriesEveryNamedFile()
    {
        foreach (var name in SettingsMigration.Files)
        {
            Write(From, name, $"contents of {name}");
        }

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(SettingsMigration.Files.Count, carried);

        foreach (var name in SettingsMigration.Files)
        {
            Assert.Equal($"contents of {name}", File.ReadAllText(Path.Combine(To, name)));
        }
    }

    [Fact]
    public void CopiesBytesExactly()
    {
        var bytes = new byte[] { 0x01, 0x00, 0xFF, 0x7F, 0x00, 0xAB };
        Directory.CreateDirectory(From);
        File.WriteAllBytes(Path.Combine(From, "deep-pass.key"), bytes);

        SettingsMigration.Carry(From, To);

        Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(To, "deep-pass.key")));
    }

    [Fact]
    public void LeavesTheSourceExactlyAsItFoundIt()
    {
        foreach (var name in SettingsMigration.Files)
        {
            Write(From, name, name);
        }

        SettingsMigration.Carry(From, To);

        // Every file still there, unchanged, and nothing new written beside them. A marker file
        // would be the obvious way to make this idempotent and is deliberately not used.
        Assert.Equal(
            SettingsMigration.Files.OrderBy(n => n, StringComparer.Ordinal),
            Directory.GetFiles(From).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal));

        foreach (var name in SettingsMigration.Files)
        {
            Assert.Equal(name, File.ReadAllText(Path.Combine(From, name)));
        }
    }

    [Theory]
    [InlineData("crash.log")]
    [InlineData("theme.xaml")]
    [InlineData("payload.exe")]
    public void DoesNotCarryAnythingOutsideTheAllowlist(string name)
    {
        Write(From, name, "should stay behind");

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(0, carried);
        Assert.False(File.Exists(Path.Combine(To, name)));
    }

    [Fact]
    public void DoesNotOverwriteSomethingAlreadySaved()
    {
        Write(From, "audience", "Developer");
        Write(To, "audience", "EndUser");

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(0, carried);
        Assert.Equal("EndUser", File.ReadAllText(Path.Combine(To, "audience")));
    }

    [Fact]
    public void ResumesARunThatOnlyGotPartWay()
    {
        foreach (var name in SettingsMigration.Files)
        {
            Write(From, name, $"old {name}");
        }

        var alreadyThere = SettingsMigration.Files.Take(3).ToList();
        foreach (var name in alreadyThere)
        {
            Write(To, name, $"new {name}");
        }

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(SettingsMigration.Files.Count - alreadyThere.Count, carried);

        foreach (var name in alreadyThere)
        {
            Assert.Equal($"new {name}", File.ReadAllText(Path.Combine(To, name)));
        }

        foreach (var name in SettingsMigration.Files.Skip(alreadyThere.Count))
        {
            Assert.Equal($"old {name}", File.ReadAllText(Path.Combine(To, name)));
        }
    }

    [Fact]
    public void DoesNothingAndCreatesNothingWhenThereIsNoOldFolder()
    {
        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(0, carried);
        Assert.False(Directory.Exists(To));
    }

    [Fact]
    public void CreatesTheNewFolderOnlyWhenSomethingIsActuallyCarried()
    {
        // An old folder that exists but holds nothing worth taking.
        Write(From, "crash.log", "noise");

        Assert.Equal(0, SettingsMigration.Carry(From, To));
        Assert.False(Directory.Exists(To));

        Write(From, "window", "0,0,800,600");

        Assert.Equal(1, SettingsMigration.Carry(From, To));
        Assert.True(Directory.Exists(To));
    }

    [Fact]
    public void RefusesToCopyAFolderOntoItself()
    {
        Write(From, "audience", "Developer");

        Assert.Equal(0, SettingsMigration.Carry(From, From));
        Assert.Equal(0, SettingsMigration.Carry(From, From.ToUpperInvariant()));
        Assert.Equal(0, SettingsMigration.Carry(From, Path.Combine(From, ".", "..", "old")));

        Assert.Equal("Developer", File.ReadAllText(Path.Combine(From, "audience")));
    }

    [Fact]
    public void SkipsADirectoryWearingAnAllowlistedName()
    {
        Directory.CreateDirectory(Path.Combine(From, "audience"));

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(0, carried);
        Assert.False(File.Exists(Path.Combine(To, "audience")));
    }

    [Fact]
    public void DoesNotRecurse()
    {
        Write(Path.Combine(From, "sub"), "deep-pass.key", "nested");

        var carried = SettingsMigration.Carry(From, To);

        Assert.Equal(0, carried);
        Assert.False(Directory.Exists(To));
    }

    [Theory]
    [InlineData(null, "to")]
    [InlineData("from", null)]
    [InlineData("", "to")]
    [InlineData("   ", "to")]
    [InlineData("from", "")]
    public void TreatsAMissingPathAsNothingToDo(string? from, string? to)
    {
        Assert.Equal(0, SettingsMigration.Carry(from, to));
    }
}
