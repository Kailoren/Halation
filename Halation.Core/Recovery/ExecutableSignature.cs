using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

using Halation.Core.Model;

namespace Halation.Core.Recovery;

/// <summary>
/// Whether a shipped executable is signed, and the VC-BIN-010 finding when it is not.
/// </summary>
/// <remarks>
/// <para>
/// Shared rather than owned by one backend, which is how it came to be missing where it was most
/// needed. The check lived inside the native recovery path, so it ran on a C or C++ binary and
/// never on a .NET one: VibeCheck could decompile an unsigned .NET application, read every line
/// of it, and never mention that nothing tied it to a publisher. Most of what this scanner is
/// pointed at is .NET or Electron.
/// </para>
/// <para>
/// <b>The finding is worded as "not signed" and never as "signature verified".</b> Nothing here
/// should be extended to claim a signature is good: that is <see cref="Authenticode"/>'s job, it
/// is what the updater uses, and the two must not be confused. What this answers is the weaker
/// and more useful question for a reader looking at a download, which is whether anything at all
/// ties the file to a publisher.
/// </para>
/// </remarks>
public static class ExecutableSignature
{
    /// <summary>
    /// Whether the file carries an embedded Authenticode certificate, or null when it could not
    /// be read as a portable executable at all.
    /// </summary>
    /// <remarks>
    /// Null rather than false for an unreadable file. "We could not look" and "we looked and
    /// found nothing" are different answers, and reporting the first as the second would accuse
    /// a developer of shipping an unsigned binary on the strength of a failed read.
    /// </remarks>
    public static bool? HasCertificate(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new PEReader(stream);

            return reader.PEHeaders.PEHeader?.CertificateTableDirectory.Size > 0;
        }
        catch (BadImageFormatException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// The VC-BIN-010 finding for an unsigned executable, or null when it is signed, catalogue
    /// signed, or could not be read.
    /// </summary>
    /// <param name="path">The file to inspect.</param>
    /// <param name="displayName">What to call it in the report.</param>
    public static Finding? Check(string path, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (HasCertificate(path) != false)
        {
            return null;
        }

        return CatalogueSigned(path) ? null : Unsigned(displayName);
    }

    /// <summary>
    /// Whether a system catalogue vouches for a file that carries no certificate of its own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Windows signs its own binaries through the security catalogue rather than by embedding
    /// anything.</b> The certificate directory of <c>notepad.exe</c> is empty and the file is
    /// validly signed, so the header read alone reports every Windows component, every driver
    /// and a good many MSI-installed applications as unsigned. Measured, and the reason this
    /// exists.
    /// </para>
    /// <para>
    /// <b><see cref="Update.Authenticode"/> cannot answer this and was tried first.</b> Its
    /// <c>WTD_CHOICE_FILE</c> verification looks only inside the file, so it returns
    /// "not code-signed" for <c>notepad.exe</c> while Windows itself reports a valid catalogue
    /// signature by Microsoft. Reaching the catalogue means hashing the file and asking whether
    /// that hash is enumerated in one, which is what this does.
    /// </para>
    /// <para>
    /// <b>Presence, matching the embedded check rather than exceeding it.</b> A hash listed in a
    /// catalogue is exactly the negation of what VC-BIN-010 claims: something ties the file to a
    /// publisher, and a modified copy would no longer match. Whether that catalogue's own
    /// signature is trusted is the stronger question <see cref="Update.Authenticode"/> answers
    /// for the updater, and deliberately not the one asked here.
    /// </para>
    /// <para>
    /// <b>Nothing goes on the network.</b> Catalogues are local files, so this costs no traffic
    /// and reveals nothing about the artifact, which the alternative of a revocation check would
    /// not have managed. It is also only reached for a file with no embedded certificate, so it
    /// never runs for the common signed case.
    /// </para>
    /// </remarks>
    private static bool CatalogueSigned(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            // SHA-256 first, then the older default. Windows 10 and 11 catalogue their own
            // components under SHA-256, but plenty of still-installed driver and application
            // catalogues predate that, and asking under the wrong algorithm finds nothing at
            // all rather than failing loudly.
            return InCatalogue(path, "SHA256") || InCatalogue(path, null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A catalogue lookup that cannot complete is not evidence either way, and it must
            // not be able to take a scan down. Treated as "no catalogue entry", which leaves
            // the reader with the accurate weaker statement that no signature was found.
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool InCatalogue(string path, string? hashAlgorithm)
    {
        var admin = IntPtr.Zero;

        try
        {
            if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0))
            {
                return false;
            }

            // Shared read. These are running system binaries as often as not, and asking for
            // exclusive access would turn a signed file into an unreadable one.
            using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            var handle = file.DangerousGetHandle();
            uint length = 0;

            // First call reports the size it needs and is expected to fail.
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref length, null, 0);

            if (length == 0)
            {
                return false;
            }

            var hash = new byte[length];

            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref length, hash, 0))
            {
                return false;
            }

            var catalogue = CryptCATAdminEnumCatalogFromHash(admin, hash, length, 0, IntPtr.Zero);

            if (catalogue == IntPtr.Zero)
            {
                return false;
            }

            CryptCATAdminReleaseCatalogContext(admin, catalogue, 0);
            return true;
        }
        finally
        {
            if (admin != IntPtr.Zero)
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catAdmin,
        IntPtr subsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catAdmin,
        IntPtr file,
        ref uint hashLength,
        byte[]? hash,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catAdmin,
        byte[] hash,
        uint hashLength,
        uint flags,
        IntPtr previous);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr catAdmin, IntPtr catalogue, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    /// <summary>
    /// The finding itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Info for the developer, Low for the reader, and the split is the whole point.</b> It
    /// was Medium on both ladders, which caps a band at 89 and relabelled every honest unsigned
    /// application as having something wrong with it. Certificates cost money, plenty of good
    /// software ships without one, and this scanner's own build is unsigned; charging a band of
    /// score for it is the scanner calling a choice a fault, which is the mistake the capability
    /// split already had to correct once.
    /// </para>
    /// <para>
    /// It is not deleted, because it is one of the few checkable facts about a download and
    /// malware rarely has an answer to it. A developer already knows their build is unsigned and
    /// can act on it whenever they choose, so Info states it and deducts nothing. Somebody
    /// deciding whether to run a stranger's program cannot know it, and for them Low reports it
    /// without pretending it is a defect. Ali's call, 2026-08-06.
    /// </para>
    /// </remarks>
    private static Finding Unsigned(string displayName) => new()
    {
        RuleId = "VC-BIN-010",
        Title = "Executable is not digitally signed",
        Severity = Severity.Info,
        UserSeverity = Severity.Low,
        Category = FindingCategory.BinaryHygiene,
        Description =
            $"{displayName} carries no Authenticode signature, so there is nothing tying it to a "
            + "publisher and no way to tell an original from a modified copy. This is a fact "
            + "about the build rather than a defect in the code.",
        Remediation =
            "Nothing to fix unless you want to. Signing a released build stops Windows warning "
            + "your users on download and lets them tell your copy from a tampered one. A "
            + "certificate costs money, and open-source projects can often get one free through "
            + "a foundation programme.",
        UserDescription =
            "This program is not digitally signed, so your computer cannot confirm who made it "
            + "or that nobody has altered it since. That is common for small and hobby projects "
            + "and is not by itself a sign of anything wrong, but it does mean you are trusting "
            + "wherever you got it from.",
        UserRemediation =
            "Only run this if you trust where you downloaded it from. Windows will warn you when "
            + "you open it, and that warning is accurate: it means nobody has vouched for the "
            + "file, not that anything bad was found in it.",
        FilePath = displayName,
    };
}
