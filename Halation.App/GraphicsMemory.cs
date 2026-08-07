using System.IO;
using System.Text.Json;

using Microsoft.Win32;

namespace Halation.App;

/// <summary>The graphics card, and how much memory it has.</summary>
/// <param name="Name">The adapter's own description, for showing back so it can be corrected.</param>
/// <param name="VideoBytes">Dedicated video memory, or zero when it could not be read.</param>
public sealed record GraphicsAdapter(string Name, long VideoBytes);

/// <summary>
/// Reads how much video memory this machine has, which decides what local model is worth running.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not from WMI.</b> <c>Win32_VideoController.AdapterRAM</c> is a 32-bit field, so every card
/// with more than 4GB reports exactly 4GB: measured on this machine, an 8GB card reported
/// 4293918720 bytes through WMI and the correct 8589934592 through the registry value beside it.
/// Advice built on the WMI number would tell every reader with a decent card to run a model two
/// sizes too small, and would be wrong in a way that looks plausible.
/// </para>
/// <para>
/// The driver writes <c>HardwareInformation.qwMemorySize</c> under its own key in the display
/// adapter class. It is read-only, present on every current driver, and needs no dependency,
/// which is the whole reason to prefer it over a DXGI interop for one number.
/// </para>
/// </remarks>
public static class GraphicsMemory
{
    /// <summary>The display adapter class. Fixed by Windows, not a guess.</summary>
    private const string DisplayClass =
        @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

    /// <summary>
    /// The largest adapter on this machine, or null when nothing could be read.
    /// </summary>
    /// <remarks>
    /// Largest rather than first, because a laptop lists its integrated adapter alongside the
    /// discrete one and the integrated entry usually comes first. Recommending a model for the
    /// wrong one of those two is the difference between a scan that takes minutes and one that
    /// takes all night, and it is exactly the case the reader can correct by hand.
    /// </remarks>
    public static GraphicsAdapter? Detect()
    {
        try
        {
            using var display = Registry.LocalMachine.OpenSubKey(DisplayClass);

            if (display is null)
            {
                return null;
            }

            GraphicsAdapter? best = null;

            foreach (var name in display.GetSubKeyNames())
            {
                // The class key also holds Properties, Configuration and similar. Only the
                // numbered ones are adapters.
                if (name.Length != 4 || !name.All(char.IsAsciiDigit))
                {
                    continue;
                }

                using var adapter = display.OpenSubKey(name);

                if (adapter is null)
                {
                    continue;
                }

                var bytes = ReadMemory(adapter);

                if (bytes <= 0 || bytes <= (best?.VideoBytes ?? 0))
                {
                    continue;
                }

                best = new GraphicsAdapter(
                    adapter.GetValue("DriverDesc") as string ?? "Graphics card", bytes);
            }

            return best;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                      or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the memory value, which is a QWORD on most drivers and bytes on some.
    /// </summary>
    private static long ReadMemory(RegistryKey adapter) =>
        adapter.GetValue("HardwareInformation.qwMemorySize") switch
        {
            long value => value,
            int value => value,
            byte[] { Length: 8 } raw => BitConverter.ToInt64(raw, 0),
            _ => 0,
        };

    /// <summary>
    /// Total physical memory, which is what a model falls back onto when it does not fit.
    /// </summary>
    public static long SystemBytes()
    {
        try
        {
            return GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        }
        catch (PlatformNotSupportedException)
        {
            return 0;
        }
    }
}

/// <summary>
/// Remembers a video memory figure the reader corrected by hand.
/// </summary>
/// <remarks>
/// <para>
/// Detection is right on an ordinary desktop and wrong often enough elsewhere to matter: a
/// laptop with two adapters, a driver that does not write the value, a virtual machine, or
/// somebody setting up for a different computer. A detected number that cannot be argued with is
/// just a guess with authority, so the reader's own figure wins and is kept.
/// </para>
/// <para>
/// Plain JSON rather than encrypted, unlike the key and endpoint stores: how much memory a
/// graphics card has is not a secret, and encrypting it would only make it harder to correct by
/// hand when this application has got it wrong.
/// </para>
/// </remarks>
public static class HardwareStore
{
    private static string Path => AppData.PathTo("hardware.json");

    private sealed record Stored(long? VideoBytes);

    /// <summary>The reader's own figure, or null when they have not given one.</summary>
    public static long? Load()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            var stored = JsonSerializer.Deserialize<Stored>(File.ReadAllText(Path));

            return stored?.VideoBytes is > 0 ? stored.VideoBytes : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException
                                      or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Saves a corrected figure, or clears it so detection takes over again.</summary>
    public static void Save(long? videoBytes)
    {
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            File.WriteAllText(Path, JsonSerializer.Serialize(new Stored(videoBytes)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
