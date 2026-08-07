using System.Reflection;
using System.Reflection.Emit;

using Halation.Core.Artifacts;
using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Exercises the decompiler against Halation.Core itself. Using a real compiler-produced
/// assembly with known contents means these tests verify that recognisable source actually
/// comes back, not merely that the call did not throw.
/// </summary>
public class DotNetRecoveryTests
{
    private static async Task<RecoveryResult> RecoverCoreAsync()
    {
        var coreAssembly = typeof(ScanReport).Assembly.Location;
        var descriptor = ArtifactDetector.Detect(coreAssembly);

        return await new DotNetRecoveryBackend().RecoverAsync(descriptor, CancellationToken.None);
    }

    [Fact]
    public void Backend_HandlesOnlyManagedAssemblies()
    {
        var backend = new DotNetRecoveryBackend();

        Assert.True(backend.CanHandle(ArtifactKind.DotNetAssembly));
        Assert.False(backend.CanHandle(ArtifactKind.ElectronApp));
        Assert.False(backend.CanHandle(ArtifactKind.NativeWindows));
    }

    [Fact]
    public async Task Decompile_RecoversCompilableLookingCSharp()
    {
        var result = await RecoverCoreAsync();

        Assert.NotEmpty(result.Files);
        Assert.All(result.Files, f =>
        {
            Assert.Equal(SourceLanguage.CSharp, f.Language);
            Assert.True(f.IsDecompiled);
            Assert.EndsWith(".cs", f.RelativePath, StringComparison.Ordinal);
        });

        var allSource = string.Join("\n", result.Files.Select(f => f.Content));
        Assert.Contains("class", allSource, StringComparison.Ordinal);
        Assert.Contains("namespace", allSource, StringComparison.Ordinal);
    }

    /// <summary>
    /// The real fidelity check: a type and a member we know exist in the source must be
    /// recognisable in the decompiled output.
    /// </summary>
    [Fact]
    public async Task Decompile_RecoversKnownTypesAndMembers()
    {
        var result = await RecoverCoreAsync();

        var scoreCalculator = result.Files.SingleOrDefault(
            f => f.RelativePath.EndsWith("ScoreCalculator.cs", StringComparison.Ordinal));

        Assert.NotNull(scoreCalculator);
        Assert.Contains("Calculate", scoreCalculator.Content, StringComparison.Ordinal);
        Assert.Contains("CategoryScores", scoreCalculator.Content, StringComparison.Ordinal);

        // The cap constants are the load-bearing values in the scoring model; seeing them
        // survive a decompile round-trip confirms method bodies are genuinely recovered.
        Assert.Contains("39", scoreCalculator.Content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Decompile_PathsAreNamespacedNotFlattened()
    {
        var result = await RecoverCoreAsync();

        Assert.Contains(result.Files, f => f.RelativePath.Contains('/'));
        Assert.Contains(
            result.Files,
            f => f.RelativePath.Contains("Model/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Decompile_ReportsHighCoverage()
    {
        var result = await RecoverCoreAsync();

        Assert.InRange(result.Coverage.Percent, 80, 100);
        Assert.Contains("Decompiled", result.Coverage.Basis, StringComparison.Ordinal);
        Assert.True(result.Coverage.RecoveredFileCount > 0);
        Assert.True(result.Coverage.RecoveredBytes > 0);
    }

    /// <summary>
    /// The scanner's own build is not strong-named, so this doubles as a check that
    /// binary-level observations survive into the result.
    /// </summary>
    [Fact]
    public async Task Decompile_ReportsBinaryHygieneFindings()
    {
        var result = await RecoverCoreAsync();

        var signing = result.Findings.SingleOrDefault(f => f.RuleId == "VC-BIN-001");

        Assert.NotNull(signing);
        Assert.Equal(FindingCategory.BinaryHygiene, signing.Category);
        Assert.Equal(Severity.Low, signing.Severity);
    }

    [Fact]
    public async Task Decompile_UnobfuscatedAssembly_IsNotFlaggedAsObfuscated()
    {
        var result = await RecoverCoreAsync();

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "VC-BIN-002");
    }

    // ---- Obfuscation and what it does to coverage --------------------------

    /// <summary>
    /// The failure this closes. Decompiling a scrambled assembly succeeds: thousands of files
    /// of <c>a.b(c)</c> come back, every one of them counted as recovered, and the application
    /// scored like a legible one that happened to have no findings. Coverage now measures what
    /// was understood rather than what was written out, so an unreadable application falls under
    /// the meaningful-coverage floor and gets the "could not analyse" band instead of a number.
    /// </summary>
    [Fact]
    public async Task ObfuscatedAssembly_DoesNotCountAsCovered()
    {
        var path = ObfuscatedAssemblyBuilder.WriteTemp();

        try
        {
            var result = await new DotNetRecoveryBackend()
                .RecoverAsync(ArtifactDetector.Detect(path), CancellationToken.None);

            Assert.Contains(result.Findings, f => f.RuleId == "VC-BIN-002");
            Assert.Equal(0, result.Coverage.Percent);

            // The source is still there and still scanned. String literals survive an
            // obfuscator, so a hardcoded wallet path is as findable in scrambled code as in
            // readable code, and dropping the files would throw that away.
            Assert.NotEmpty(result.Files);

            // The number has to explain itself, or "0 of 30 types" reads as a decompiler that
            // failed rather than one that worked on something nobody can read.
            Assert.Contains("obfuscator", result.Coverage.Basis, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task NativeBinary_YieldsNoSourceRatherThanThrowing()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(File.Exists(kernel32));

        // Force the managed backend down the native path to confirm it degrades cleanly.
        var descriptor = new ArtifactDescriptor
        {
            Path = kernel32,
            Kind = ArtifactKind.DotNetAssembly,
            IsDirectory = false,
            Bytes = new FileInfo(kernel32).Length,
        };

        var result = await new DotNetRecoveryBackend()
            .RecoverAsync(descriptor, CancellationToken.None);

        Assert.Empty(result.Files);
        Assert.Equal(0, result.Coverage.Percent);
    }
}

/// <summary>
/// Builds an assembly whose type names have been taken out, which is what an obfuscator leaves
/// behind.
/// </summary>
/// <remarks>
/// Emitted rather than checked in, for the reason the NSIS and asar builders give: this
/// repository is public and carries no third-party binaries, and a real obfuscated sample would
/// be somebody else's code.
/// </remarks>
internal static class ObfuscatedAssemblyBuilder
{
    public static byte[] Build()
    {
        var builder = new PersistedAssemblyBuilder(
            new AssemblyName("Scrambled"), typeof(object).Assembly);

        var module = builder.DefineDynamicModule("Scrambled.dll");

        // Comfortably past the heuristic's floor of twenty types, all named the way an
        // obfuscator names them.
        foreach (var name in Enumerable.Range(0, 30).Select(i => $"{(char)('a' + (i % 26))}{i / 26}"))
        {
            var type = module.DefineType(name, TypeAttributes.Public);

            type.DefineMethod("m", MethodAttributes.Public | MethodAttributes.Static)
                .GetILGenerator()
                .Emit(OpCodes.Ret);

            type.CreateType();
        }

        using var stream = new MemoryStream();
        builder.Save(stream);

        return stream.ToArray();
    }

    public static string WriteTemp()
    {
        var path = Path.Combine(Path.GetTempPath(), $"halation-obf-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(path, Build());

        return path;
    }
}
