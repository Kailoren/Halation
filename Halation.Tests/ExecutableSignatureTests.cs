using Halation.Core.Model;
using Halation.Core.Recovery;
using Halation.Core.Scoring;

namespace Halation.Tests;

/// <summary>
/// Whether anything ties a shipped executable to a publisher, which is VC-BIN-010.
/// </summary>
/// <remarks>
/// <para>
/// Both defects these were written for were found by measurement against real files while every
/// synthetic test passed, so the two that matter most run against binaries on the machine rather
/// than fixtures. They return early off Windows, where there is no catalogue to consult and no
/// application this scanner targets.
/// </para>
/// <para>
/// The check used to live inside the native recovery path alone, so it ran on a C or C++ binary
/// and never on a .NET one. Most of what Halation is pointed at is .NET or Electron.
/// </para>
/// </remarks>
public class ExecutableSignatureTests
{
    private const string Notepad = @"C:\Windows\System32\notepad.exe";

    [Fact]
    public void A_catalogue_signed_binary_is_not_called_unsigned()
    {
        // Windows signs its own components through the security catalogue, so the certificate
        // directory is empty while the file is validly signed. Reading the header alone reported
        // notepad.exe as unsigned, and WinVerifyTrust's file check agrees with the header rather
        // than with Windows: it answers "not code-signed" for a file Explorer shows as signed by
        // Microsoft. Only the catalogue lookup gets this right.
        if (!OperatingSystem.IsWindows() || !File.Exists(Notepad))
        {
            return;
        }

        Assert.False(ExecutableSignature.HasCertificate(Notepad));
        Assert.Null(ExecutableSignature.Check(Notepad, "notepad.exe"));
    }

    [Fact]
    public void A_genuinely_unsigned_build_still_raises_it()
    {
        // The other direction, without which the test above could be satisfied by never
        // reporting anything. The test assembly is a plain unsigned build.
        var self = typeof(ExecutableSignatureTests).Assembly.Location;

        if (!File.Exists(self))
        {
            return;
        }

        Assert.False(ExecutableSignature.HasCertificate(self));

        var finding = ExecutableSignature.Check(self, "tests.dll");

        Assert.NotNull(finding);
        Assert.Equal("VC-BIN-010", finding.RuleId);
    }

    [Fact]
    public void It_is_information_for_the_developer_and_low_for_the_reader()
    {
        // Ali's call, 2026-08-06. It was Medium on both ladders, which caps a band at 89 and
        // relabelled every honest unsigned application as having something wrong with it.
        // Deleting the check was the alternative and was rejected: it is one of the few
        // checkable facts about a download, and the defect was the rating rather than the scope.
        var self = typeof(ExecutableSignatureTests).Assembly.Location;

        if (!File.Exists(self))
        {
            return;
        }

        var finding = ExecutableSignature.Check(self, "tests.dll");

        Assert.NotNull(finding);
        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(Severity.Low, finding.UserSeverity);

        // Info deducts nothing, so a developer's own unsigned build cannot cost them a band.
        Assert.Equal(0, ScoreCalculator.WeightFor(finding.Severity));
    }

    [Fact]
    public void An_unreadable_file_is_not_accused_of_being_unsigned()
    {
        // Null rather than false. "We could not look" and "we looked and found nothing" are
        // different answers, and reporting the first as the second would accuse a developer of
        // shipping an unsigned binary on the strength of a failed read.
        var text = Path.Combine(Path.GetTempPath(), $"vc-not-a-pe-{Guid.NewGuid():N}.txt");

        try
        {
            File.WriteAllText(text, "This is not a portable executable.");

            Assert.Null(ExecutableSignature.HasCertificate(text));
            Assert.Null(ExecutableSignature.Check(text, "notes.txt"));
        }
        finally
        {
            File.Delete(text);
        }
    }

    [Fact]
    public void A_missing_file_is_not_accused_either()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"vc-absent-{Guid.NewGuid():N}.exe");

        Assert.Null(ExecutableSignature.HasCertificate(missing));
        Assert.Null(ExecutableSignature.Check(missing, "gone.exe"));
    }

    [Fact]
    public void The_wording_never_claims_a_signature_was_verified()
    {
        // The guarantee the whole class rests on. This answers whether anything is attached,
        // not whether it checks out, and a reader who took it for the stronger claim would be
        // relying on a check that never ran. Authenticode is where the stronger claim lives.
        var self = typeof(ExecutableSignatureTests).Assembly.Location;

        if (!File.Exists(self))
        {
            return;
        }

        var finding = ExecutableSignature.Check(self, "tests.dll");

        Assert.NotNull(finding);

        foreach (var text in new[]
                 {
                     finding.Description, finding.UserDescription,
                     finding.Remediation, finding.UserRemediation,
                 })
        {
            Assert.DoesNotContain("verified", text!, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("trusted", text!, StringComparison.OrdinalIgnoreCase);
        }

        // And it does not tell somebody their build is broken.
        Assert.DoesNotContain("Do not run", finding.Remediation!, StringComparison.OrdinalIgnoreCase);
    }
}
