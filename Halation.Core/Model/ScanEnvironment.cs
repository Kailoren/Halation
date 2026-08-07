using System.Runtime.InteropServices;

namespace Halation.Core.Model;

/// <summary>
/// The machine a scan ran on, and what answered the deep pass, recorded in the exported report.
/// </summary>
/// <remarks>
/// <para>
/// <b>For the reader to send, never for this application to send.</b> Nothing here is transmitted
/// anywhere: it is written into the export so that somebody choosing to file a report has the
/// facts in front of them, in a file they can read first. That is the same promise the rest of
/// the product makes, and it would be a poor trade to break it in the feature that exists to
/// improve the product.
/// </para>
/// <para>
/// It exists because the local deep pass has been measured on <b>exactly one configuration</b>,
/// a 7B model on an 8GB card. Whether the answer is better on a 24GB card, or on a 70B model, or
/// on a processor with no card at all, is unknown, and a report saying "it was bad for me" is
/// worth very little without the machine it was bad on.
/// </para>
/// <para>
/// Deliberately narrow. The graphics card, the memory, the model and the runtime are what change
/// the answer. The user name, the machine name and the paths on it do not, so they are not here.
/// </para>
/// </remarks>
public sealed record ScanEnvironment
{
    public string? OperatingSystem { get; init; }

    public string? Architecture { get; init; }

    public int ProcessorCount { get; init; }

    /// <summary>Installed system memory, or zero when it could not be read.</summary>
    public long SystemMemoryBytes { get; init; }

    /// <summary>The graphics adapter's name, or null when none was found.</summary>
    public string? GraphicsAdapter { get; init; }

    /// <summary>Dedicated video memory, or zero when there is none or it could not be read.</summary>
    public long GraphicsMemoryBytes { get; init; }

    /// <summary>Which of the three routes answered, if the deep pass ran.</summary>
    public string? DeepPassRoute { get; init; }

    /// <summary>The model that answered, as configured. Null for the routes that choose it.</summary>
    public string? DeepPassModel { get; init; }

    /// <summary>
    /// The local runtime serving the endpoint, when one was detected.
    /// </summary>
    /// <remarks>
    /// Names the runtime rather than the address. Which of Ollama or LM Studio is answering
    /// changes the default context length and therefore whether a file arrived whole, which is
    /// the first thing worth knowing about a disappointing local result.
    /// </remarks>
    public string? DeepPassRuntime { get; init; }

    /// <summary>Whether the deep pass stayed on this machine.</summary>
    public bool? DeepPassRanLocally { get; init; }

    /// <summary>
    /// What can be told without asking the operating system anything platform-specific.
    /// </summary>
    /// <remarks>
    /// The graphics adapter and the installed memory are read through the registry, which is a
    /// Windows API and lives in the application project. This half is here so a report is never
    /// missing the easy facts because the hard ones could not be gathered.
    /// </remarks>
    public static ScanEnvironment Describe() => new()
    {
        OperatingSystem = RuntimeInformation.OSDescription,
        Architecture = RuntimeInformation.OSArchitecture.ToString(),
        ProcessorCount = Environment.ProcessorCount,
    };
}
