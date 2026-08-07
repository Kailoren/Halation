using System.Runtime.InteropServices;
using System.Text;

namespace VibeCheck.Core.Update;

/// <summary>
/// Whether this process is running from an installed package rather than as a loose
/// executable.
/// </summary>
/// <remarks>
/// <para>
/// The same build behaves differently depending on how it was installed, and this is how it
/// tells. A copy installed from the Microsoft Store is updated by the Store, and a Store
/// application updating itself is not merely redundant: replacing your own binary outside the
/// Store is against Store policy, so shipping the self-updater live inside a package is a
/// certification risk rather than a cosmetic problem.
/// </para>
/// <para>
/// Asked of the operating system rather than guessed from the file layout. Two heuristics that
/// look like they would work do not. A package install directory is read-only, so the
/// writability probe refuses correctly but says "cannot write to its own folder", which reads
/// as a permissions fault. And a packaged build ships loose files including
/// <c>Halation.deps.json</c>, which the development-build check treats as proof of running
/// from build output, so a Store install would announce itself as a developer's working copy.
/// Both were observed in a real package built from this project.
/// </para>
/// </remarks>
public static class PackageIdentity
{
    /// <summary>
    /// What <c>GetCurrentPackageFullName</c> returns when the process has no package identity.
    /// </summary>
    /// <remarks>
    /// The documented way to ask the question: there is no "is packaged" call, only this one
    /// failing in a specific way. Any other result, including the buffer being too small, means
    /// a package name exists to be read.
    /// </remarks>
    private const int AppModelErrorNoPackage = 15700;

    /// <summary>
    /// True when the process has package identity, i.e. it was installed as an MSIX.
    /// </summary>
    /// <remarks>
    /// Evaluated once. Package identity is fixed for the lifetime of a process, and the call is
    /// a kernel round trip that several code paths would otherwise repeat.
    /// </remarks>
    public static bool IsPackaged { get; } = Detect();

    private static bool Detect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            var length = 0;

            // Called with no buffer purely to read the return code. A packaged process answers
            // ERROR_INSUFFICIENT_BUFFER here, which is a yes; only the no-package code is a no.
            return GetCurrentPackageFullName(ref length, null) != AppModelErrorNoPackage;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            // Present since Windows 8. Treated as unpackaged rather than fatal, because being
            // unable to ask is not a reason to refuse to run.
            return false;
        }
    }

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref int length, StringBuilder? name);
}
