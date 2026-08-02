using System.Reflection.PortableExecutable;

using VibeCheck.Core.Artifacts;
using VibeCheck.Core.Model;

namespace VibeCheck.Core.Recovery;

/// <summary>
/// Handles native binaries, where no source recovery is possible.
/// </summary>
/// <remarks>
/// <para>
/// This is the scanner's shallowest tier and it is important that the report says so. A
/// native executable cannot be decompiled to anything a source rule can meaningfully read,
/// so what remains is binary hygiene: is it signed, and are the exploit mitigations on.
/// </para>
/// <para>
/// Coverage is therefore reported as zero with an explicit list of what could not be
/// checked. A clean result here means "nothing was inspected", and conflating that with
/// "nothing is wrong" is precisely the failure this design exists to avoid.
/// </para>
/// </remarks>
public sealed class NativeRecoveryBackend : IRecoveryBackend
{
    public bool CanHandle(ArtifactKind kind) =>
        kind is ArtifactKind.NativeWindows or ArtifactKind.Unknown;

    public Task<RecoveryResult> RecoverAsync(
        ArtifactDescriptor artifact,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        cancellationToken.ThrowIfCancellationRequested();

        var findings = new List<Finding>();
        var basis = "This artifact contains no recoverable source.";
        var limitations = new List<string>
        {
            "Hardcoded credentials and API keys (requires readable source).",
            "Injection, unsafe deserialisation, and other code-level flaws.",
            "Authentication and access-control logic.",
            "Dependency versions and their known vulnerabilities.",
        };

        if (artifact.Kind == ArtifactKind.NativeWindows)
        {
            if (artifact.IsDirectory)
            {
                basis = "This application is built from native binaries, which cannot be "
                        + "decompiled to analysable source. Nothing in it was read.";
            }
            else
            {
                findings.AddRange(InspectPortableExecutable(artifact));
                basis = "Native binary: hygiene checks only, no source could be recovered.";
            }
        }

        return Task.FromResult(new RecoveryResult
        {
            Files = [],
            Findings = findings,
            Coverage = new CoverageReport
            {
                Percent = 0,
                Basis = basis,
                ChecksNotPossible = limitations,
            },
        });
    }

    private static IEnumerable<Finding> InspectPortableExecutable(ArtifactDescriptor artifact)
    {
        var findings = new List<Finding>();

        PEHeaders headers;
        bool hasCertificate;

        try
        {
            using var stream = File.OpenRead(artifact.Path);
            using var reader = new PEReader(stream);

            headers = reader.PEHeaders;

            // An Authenticode signature lives in the certificate directory. Its presence
            // does not prove the signature is valid or the publisher trustworthy, so the
            // finding below is worded as "unsigned", never as "signature verified".
            hasCertificate = headers.PEHeader?.CertificateTableDirectory.Size > 0;
        }
        catch (BadImageFormatException)
        {
            return findings;
        }
        catch (IOException)
        {
            return findings;
        }

        if (!hasCertificate)
        {
            findings.Add(new Finding
            {
                RuleId = "VC-BIN-010",
                Title = "Executable is not digitally signed",
                Severity = Severity.Medium,
                UserSeverity = Severity.Medium,
                UserDescription =
                    "This program is not digitally signed, so your computer cannot confirm who made it or "
                    + "that it has not been altered since. This is common for small and hobby projects, but "
                    + "it does mean you are trusting the download itself.",
                UserRemediation =
                    "Only run this if you trust where you got it from. Windows will warn you when you "
                    + "open it, and that warning is accurate.",
                Category = FindingCategory.BinaryHygiene,
                Description =
                    $"{artifact.Name} carries no Authenticode signature, so there is nothing tying "
                    + "it to a publisher and no way to tell an original from a modified copy.",
                Remediation =
                    "Only run unsigned executables from a source you independently trust. "
                    + "Developers should sign released builds with a code-signing certificate.",
                FilePath = artifact.Name,
            });
        }

        var characteristics = headers.PEHeader?.DllCharacteristics ?? default;

        if ((characteristics & DllCharacteristics.DynamicBase) == 0)
        {
            findings.Add(Mitigation(
                "VC-BIN-011",
                "Address space layout randomisation is disabled",
                artifact.Name,
                "The binary is not built with ASLR, so its code loads at a predictable address. "
                + "That makes memory-corruption bugs substantially easier to exploit reliably.",
                "Rebuild with /DYNAMICBASE (it is on by default in modern toolchains)."));
        }

        if ((characteristics & DllCharacteristics.NxCompatible) == 0)
        {
            findings.Add(Mitigation(
                "VC-BIN-012",
                "Data execution prevention is not enabled",
                artifact.Name,
                "The binary is not marked NX-compatible, so data pages may be executable and "
                + "injected code can run directly from the stack or heap.",
                "Rebuild with /NXCOMPAT."));
        }

        return findings;
    }

    private static Finding Mitigation(
        string ruleId,
        string title,
        string file,
        string description,
        string remediation) => new()
        {
            RuleId = ruleId,
            Title = title,
            Severity = Severity.Low,
            Category = FindingCategory.BinaryHygiene,
            Description = description,

            // The same for every hardening flag on purpose. Which protection is missing is a
            // detail only the developer can act on; what the reader needs is that the app was
            // built without a standard safety net, and that is one sentence rather than three.
            UserSeverity = Severity.Low,
            UserDescription =
                "This program was built without one of the standard protections that modern "
                + "compilers add to make bugs harder to exploit. It does not mean the app is "
                + "unsafe, only that if it does turn out to have a flaw, that flaw is easier to "
                + "take advantage of than it needed to be.",
            Remediation = remediation,
            FilePath = file,
        };
}
