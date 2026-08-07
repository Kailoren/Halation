using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Halation.Core.Update;

/// <summary>What Windows says about a file's code signature.</summary>
public sealed record SignatureVerdict
{
    /// <summary>
    /// Whether Windows validated the signature, the certificate chain and its revocation state.
    /// Nothing less counts: a file carrying a certificate is not a file whose signature checks out.
    /// </summary>
    public required bool Trusted { get; init; }

    /// <summary>True when the file carries no signature at all, as opposed to a bad one.</summary>
    public required bool Unsigned { get; init; }

    /// <summary>The signer's distinguished name, present only when the signature is trusted.</summary>
    public string? Subject { get; init; }

    public string? Issuer { get; init; }

    /// <summary>The signer in one readable phrase, for the interface.</summary>
    public string? CommonName { get; init; }

    /// <summary>What happened, in a line worth showing someone.</summary>
    public required string Detail { get; init; }
}

/// <summary>
/// Asks Windows to verify a file's Authenticode signature.
/// </summary>
/// <remarks>
/// <para>
/// This is the gate on replacing the running application with a download. VibeCheck's own
/// VC-MAL-007 tells other applications that an updater must verify what it fetched against
/// something better than a hash served from the same place as the file, and an application
/// that says so while doing otherwise is worth less than one that says nothing.
/// </para>
/// <para>
/// WinVerifyTrust rather than reading the certificate out of the file: extracting the embedded
/// certificate proves only that a certificate is embedded, which anyone can arrange by copying
/// the signature blob from a signed file. Only the trust provider checks that the signature
/// actually covers these bytes and that the chain behind it is one this machine trusts.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;
    private const uint WTD_REVOCATION_CHECK_CHAIN = 0x40;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int CERT_E_REVOCATION_FAILURE = unchecked((int)0x800B010E);
    private const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);

    /// <summary>
    /// Verifies a file and, when it checks out, reports who signed it.
    /// </summary>
    /// <remarks>
    /// The signer is read only after the trust provider is satisfied, so the name returned is
    /// one that verifiably signed these bytes rather than one found inside them.
    /// </remarks>
    public static SignatureVerdict Verify(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var result = CallWinVerifyTrust(path);

        if (result != 0)
        {
            return new SignatureVerdict
            {
                Trusted = false,
                Unsigned = result == TRUST_E_NOSIGNATURE,
                Detail = Describe(result),
            };
        }

        try
        {
            // Suppressed rather than replaced: the obsoletion points at X509CertificateLoader,
            // which loads a certificate from bytes you already have and has no equivalent for
            // "read the signer out of an Authenticode signature". The alternative is a second
            // round of P/Invoke into CryptQueryObject to reach the same certificate. The bytes
            // it returns do go through the loader below.
#pragma warning disable SYSLIB0057
            var raw = X509Certificate.CreateFromSignedFile(path).GetRawCertData();
#pragma warning restore SYSLIB0057

            using var certificate = X509CertificateLoader.LoadCertificate(raw);

            var name = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            return new SignatureVerdict
            {
                Trusted = true,
                Unsigned = false,
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                CommonName = string.IsNullOrWhiteSpace(name) ? certificate.Subject : name,
                Detail = $"Signed by {(string.IsNullOrWhiteSpace(name) ? certificate.Subject : name)}.",
            };
        }
        catch (CryptographicException ex)
        {
            // Windows trusted it and the certificate could not be read back, which should not
            // happen. Treated as a failure rather than reported as trusted with no signer,
            // because the signer is the whole point of asking.
            return new SignatureVerdict
            {
                Trusted = false,
                Unsigned = false,
                Detail = $"The signature verified but its certificate could not be read ({ex.Message}).",
            };
        }
    }

    private static int CallWinVerifyTrust(string path)
    {
        var filePath = Marshal.StringToHGlobalUni(path);
        var fileInfoPtr = IntPtr.Zero;

        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = filePath,
                FileHandle = IntPtr.Zero,
                KnownSubject = IntPtr.Zero,
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var data = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                PolicyCallbackData = IntPtr.Zero,
                SIPClientData = IntPtr.Zero,

                // No dialogs. This runs behind a button in our own interface, and a system
                // prompt appearing from underneath it would be indistinguishable from the
                // download having done something.
                UIChoice = WTD_UI_NONE,

                // Revocation is checked across the chain and a check that cannot complete is a
                // failure, not a pass. The machine has just downloaded sixty megabytes, so it
                // has the network this needs; the case being guarded against is a signing key
                // known to be stolen and revoked, which is exactly when it must not be skipped.
                RevocationChecks = WTD_REVOKE_WHOLECHAIN,
                UnionChoice = WTD_CHOICE_FILE,
                FileInfoPtr = fileInfoPtr,
                StateAction = WTD_STATEACTION_VERIFY,
                StateData = IntPtr.Zero,
                URLReference = IntPtr.Zero,
                ProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_CHAIN,
                UIContext = 0,
                SignatureSettings = IntPtr.Zero,
            };

            var result = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);

            // The provider holds state until it is told to let go, whatever the verdict was.
            data.StateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);

            return result;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }

            Marshal.FreeHGlobal(filePath);
        }
    }

    private static string Describe(int result) => result switch
    {
        TRUST_E_NOSIGNATURE => "This file is not code-signed.",
        TRUST_E_BAD_DIGEST => "The signature does not match the file's contents.",
        TRUST_E_EXPLICIT_DISTRUST => "This signature is explicitly distrusted on this machine.",
        TRUST_E_SUBJECT_NOT_TRUSTED => "The signer is not trusted on this machine.",
        CERT_E_UNTRUSTEDROOT => "The signing certificate does not chain to a trusted root.",
        CERT_E_CHAINING => "The signing certificate's chain could not be built.",
        CERT_E_EXPIRED => "The signing certificate had expired and the signature is not timestamped.",
        CERT_E_REVOKED => "The signing certificate has been revoked.",
        CERT_E_REVOCATION_FAILURE => "Whether the signing certificate is revoked could not be checked.",
        CRYPT_E_FILE_ERROR => "The file could not be read for verification.",
        _ => $"Windows refused the signature (0x{result:X8}).",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPtr;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr URLReference;
        public uint ProvFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr window, Guid action, ref WinTrustData data);
}
