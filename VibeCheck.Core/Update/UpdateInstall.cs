using System.IO;

namespace VibeCheck.Core.Update;

/// <summary>Whether this copy of the application is in a position to replace itself, and why.</summary>
public sealed record InstallCapability
{
    public required bool CanInstall { get; init; }

    /// <summary>
    /// Said plainly, and shown to the reader when the answer is no. An update button that is
    /// simply absent tells somebody nothing about what to do instead.
    /// </summary>
    public required string Detail { get; init; }

    /// <summary>The file that would be replaced.</summary>
    public string? TargetPath { get; init; }

    /// <summary>
    /// The signer a downloaded build has to match. Null when there is nothing to match against,
    /// which is itself a reason not to install.
    /// </summary>
    public string? ExpectedPublisher { get; init; }
}

/// <summary>
/// The rules under which this application will overwrite itself with something it downloaded.
/// </summary>
/// <remarks>
/// Written to be refused easily. The interesting states are all the ones where an update is
/// available and installing it is still the wrong thing to do, and each of them says so in
/// words rather than by hiding a button.
/// </remarks>
public static class UpdateInstall
{
    /// <summary>
    /// The publisher whose signature is accepted on a downloaded build.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null until releases are code-signed</b>, which is what currently stops this
    /// application from installing anything: with no expected signer there is nothing to check
    /// a download against, so the update is announced and fetched by hand instead.
    /// </para>
    /// <para>
    /// When a certificate is in place, set this to the full subject line of the signing
    /// certificate, exactly as <see cref="SignatureVerdict.Subject"/> reports it, for example
    /// <c>CN=Kailoren, O=Kailoren, L=..., S=..., C=GB</c>. The subject rather than a thumbprint
    /// on purpose: short-lived certificates are reissued constantly, and a pinned thumbprint
    /// would stop updates working the first time one was renewed.
    /// </para>
    /// </remarks>
    /// <remarks>
    /// A field rather than a constant so that the code reading it stays reachable while it is
    /// null. As a constant the compiler folds it away and warns that the check can never match,
    /// which is true today and stops being true the moment somebody fills it in.
    /// </remarks>
    public static readonly string? PinnedPublisher = null;

    /// <summary>The renamed previous build, kept until the next launch can delete it.</summary>
    public const string SupersededSuffix = ".superseded";

    /// <summary>Extension on a build being fetched, so a half-finished one is recognisable.</summary>
    public const string DownloadSuffix = ".download";

    /// <summary>
    /// Works out whether this copy could install an update, without touching the network.
    /// </summary>
    /// <remarks>
    /// Every refusal here is a real situation rather than a defensive check: run from a build
    /// output, installed somewhere the current account cannot write, or unsigned and therefore
    /// with no publisher for a download to be held to.
    /// </remarks>
    public static InstallCapability Assess(string? processPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Refuse("Updates can only be installed on Windows.");
        }

        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
        {
            return Refuse("The running executable could not be located.");
        }

        var directory = Path.GetDirectoryName(processPath);

        if (string.IsNullOrEmpty(directory))
        {
            return Refuse("The running executable could not be located.");
        }

        // A framework-dependent build leaves its dependency manifest beside the launcher. That
        // is a build output rather than an installation, and replacing it with a released
        // single file would delete somebody's working directory in exchange for an application
        // that no longer matches its own source.
        var manifest = Path.Combine(
            directory, Path.GetFileNameWithoutExtension(processPath) + ".deps.json");

        if (File.Exists(manifest))
        {
            return Refuse("This is a development build running from its build output.");
        }

        if (!IsWritable(directory))
        {
            return Refuse($"VibeCheck cannot write to its own folder ({directory}).");
        }

        var expected = ExpectedPublisher(processPath);

        if (expected is null)
        {
            return new InstallCapability
            {
                CanInstall = false,
                TargetPath = processPath,

                // The honest version of "this feature is not finished". VC-MAL-007 tells other
                // applications not to run a download they cannot verify, and this one is held
                // to it: no publisher to check against means no install, not a quiet exception.
                Detail = "This build is not code-signed, so a download cannot be checked "
                         + "against a known publisher. VibeCheck will not replace itself with "
                         + "something it cannot verify.",
            };
        }

        return new InstallCapability
        {
            CanInstall = true,
            TargetPath = processPath,
            ExpectedPublisher = expected,
            Detail = $"Updates are accepted only if signed by {expected}.",
        };
    }

    /// <summary>
    /// Who a downloaded build has to be signed by: the pinned publisher if one is set, and
    /// otherwise whoever signed the copy already running.
    /// </summary>
    /// <remarks>
    /// Falling back to the running copy is deliberate rather than lax. It is the build this
    /// machine already chose to run, so requiring its successor to carry the same signature
    /// keeps an update in the same hands as the installation, and it starts working the day
    /// releases are signed without waiting for a code change here.
    /// </remarks>
    private static string? ExpectedPublisher(string processPath)
    {
        if (PinnedPublisher is { Length: > 0 } pinned)
        {
            return pinned;
        }

        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var running = Authenticode.Verify(processPath);

        return running is { Trusted: true, Subject.Length: > 0 } ? running.Subject : null;
    }

    /// <summary>
    /// Why a downloaded file must not be installed, or null when it may be.
    /// </summary>
    public static string? Reject(string downloadedPath, InstallCapability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);

        if (!capability.CanInstall || capability.ExpectedPublisher is not { Length: > 0 } expected)
        {
            return capability.Detail;
        }

        if (!OperatingSystem.IsWindows())
        {
            return "Updates can only be installed on Windows.";
        }

        var verdict = Authenticode.Verify(downloadedPath);

        if (!verdict.Trusted)
        {
            return $"The download was rejected. {verdict.Detail}";
        }

        // Ordinal and whole-string. A signer that is nearly the expected one is not the
        // expected one, and this is the comparison the whole download hangs on.
        if (!string.Equals(verdict.Subject, expected, StringComparison.Ordinal))
        {
            return $"The download is signed by {verdict.CommonName ?? verdict.Subject}, "
                   + $"which is not the publisher of this build.";
        }

        return null;
    }

    /// <summary>
    /// Puts the new build in place of the old one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Windows will not let a running executable be overwritten or deleted, but it will let one
    /// be renamed, which is what makes this possible without a second program to do it after
    /// this one exits. The old build is moved aside, the new one takes its name, and the next
    /// launch deletes what was moved.
    /// </para>
    /// <para>
    /// The rollback matters: a failure between the two moves would otherwise leave the machine
    /// with no VibeCheck at all under the name every shortcut points at.
    /// </para>
    /// </remarks>
    public static void Replace(string downloadedPath, string targetPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(downloadedPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

        var superseded = targetPath + SupersededSuffix;

        ClearSuperseded(superseded);

        File.Move(targetPath, superseded);

        try
        {
            File.Move(downloadedPath, targetPath);
        }
        catch
        {
            File.Move(superseded, targetPath);
            throw;
        }
    }

    /// <summary>
    /// Makes room for a build about to be moved aside, without deleting anything that is still
    /// in use.
    /// </summary>
    private static void ClearSuperseded(string superseded)
    {
        if (!File.Exists(superseded))
        {
            return;
        }

        try
        {
            File.Delete(superseded);
        }
        catch (IOException)
        {
            // Still running, which happens when an update follows an update within one session.
            // A locked file cannot be deleted but can be renamed, so it is moved out of the way
            // and left for a later sweep.
            File.Move(superseded, $"{superseded}-{Guid.NewGuid():N}");
        }
    }

    /// <summary>
    /// Deletes what previous updates left behind. Called at startup, when the build that was
    /// replaced is no longer running and can finally go.
    /// </summary>
    /// <remarks>
    /// Matched by exact name rather than by wildcard: this deletes files in the application's
    /// own folder, which for a portable single file is a folder somebody else chose and may
    /// keep their own things in.
    /// </remarks>
    public static int SweepSuperseded(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return 0;
        }

        var directory = Path.GetDirectoryName(processPath);

        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            return 0;
        }

        var name = Path.GetFileName(processPath);
        var removed = 0;

        foreach (var file in Directory.EnumerateFiles(directory))
        {
            var candidate = Path.GetFileName(file);

            var isLeftover = candidate.StartsWith(name + SupersededSuffix, StringComparison.Ordinal)
                             || (candidate.StartsWith(name + '.', StringComparison.Ordinal)
                                 && candidate.EndsWith(DownloadSuffix, StringComparison.Ordinal));

            if (!isLeftover)
            {
                continue;
            }

            try
            {
                File.Delete(file);
                removed++;
            }
            catch (IOException)
            {
                // The build being replaced can still be exiting. Next launch gets it.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    private static bool IsWritable(string directory)
    {
        var probe = Path.Combine(directory, $".vibecheck-write-{Guid.NewGuid():N}");

        try
        {
            using (File.Create(probe, 1, FileOptions.DeleteOnClose))
            {
                return true;
            }
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static InstallCapability Refuse(string detail) => new()
    {
        CanInstall = false,
        Detail = detail,
    };
}
