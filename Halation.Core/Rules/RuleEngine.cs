using System.Collections.Concurrent;

using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Core.Rules;

/// <summary>What the rule pass produced, including anything it could not complete.</summary>
public sealed record RuleEngineResult
{
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>
    /// Checks that did not finish, so the report can distinguish "nothing found" from
    /// "not looked at".
    /// </summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    /// <summary>Every check in the catalog and how it ended, passes included.</summary>
    public IReadOnlyList<CheckOutcome> Checks { get; init; } = [];

    public int FilesAnalysed { get; init; }

    /// <summary>
    /// Matches dropped as pattern definitions rather than uses.
    /// </summary>
    /// <remarks>
    /// Reported rather than merely applied. See <see cref="Heuristics.IsPatternDefinition"/>:
    /// this is the count of times the scanner decided a match was a rule table entry rather
    /// than code, and a reader is entitled to know it made that decision at all.
    /// </remarks>
    public int MatchesDiscounted { get; init; }
}

/// <summary>
/// Runs the rule catalog across recovered source.
/// </summary>
public sealed class RuleEngine
{
    /// <summary>The full catalog, in the order findings are grouped for review.</summary>
    public static IReadOnlyList<IRule> DefaultRules { get; } =
    [
        .. MaliciousBehaviourRules.All,
        .. SecretRules.All,
        .. ConfigurationRules.All,
        .. CodeSafetyRules.All,
        .. UntrustedInputRules.All,
    ];

    private readonly IReadOnlyList<IRule> _rules;

    public RuleEngine(IEnumerable<IRule>? rules = null) =>
        _rules = rules?.ToList() ?? DefaultRules;

    public IReadOnlyList<IRule> Rules => _rules;

    /// <summary>
    /// Evaluates every applicable rule against every recovered file.
    /// </summary>
    /// <remarks>
    /// Files are processed in parallel because the work is CPU-bound regex over independent
    /// inputs, and a large source tree is thousands of files against dozens of rules.
    /// </remarks>
    public RuleEngineResult Analyse(
        IReadOnlyList<RecoveredFile> files,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);

        var findings = new ConcurrentBag<Finding>();
        var limitations = new ConcurrentDictionary<string, byte>();
        var completed = 0;

        // Counted per rule so a pass can say how much it was worth. A check that examined one
        // file and a check that examined four hundred are not the same reassurance.
        var examined = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        var fired = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        var discounted = 0;

        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Environment.ProcessorCount,
        };

        Parallel.ForEach(files, options, file =>
        {
            var context = new RuleContext(file);

            foreach (var rule in _rules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!rule.AppliesTo(file))
                {
                    continue;
                }

                examined.AddOrUpdate(rule.Id, 1, (_, count) => count + 1);

                try
                {
                    foreach (var finding in rule.Examine(context))
                    {
                        findings.Add(Adjust(finding, file));
                        fired.TryAdd(rule.Id, 0);
                    }
                }
                catch (RuleTimeoutException)
                {
                    // Recorded rather than swallowed: an unfinished check is not a clean one.
                    limitations.TryAdd(
                        $"Check {rule.Id} did not complete on {file.RelativePath} and was skipped.",
                        0);

                    // And it does not get to be counted as a pass either. Backing the file out
                    // of the tally is what stops a rule that timed out everywhere from
                    // reporting itself clean.
                    examined.AddOrUpdate(rule.Id, 0, (_, count) => count - 1);
                }
            }

            if (context.DiscountedMatches > 0)
            {
                Interlocked.Add(ref discounted, context.DiscountedMatches);
            }

            progress?.Report(Interlocked.Increment(ref completed));
        });

        // Checks written for a language this application does not contain looked at nothing, and
        // a reader is owed the reason. Without it the checks list shows them as "could not run"
        // beside no explanation, which reads as a fault in the scan rather than as a fact about
        // the code. Silent when every check applied, on the same principle as the dependency
        // caveat: an application with no gap has nothing to be warned about.
        if (InapplicableChecks(examined, files) is { } notApplicable)
        {
            limitations.TryAdd(notApplicable, 0);
        }

        return new RuleEngineResult
        {
            Findings = Deduplicate(findings),
            Limitations = [.. limitations.Keys.Order(StringComparer.Ordinal)],
            FilesAnalysed = files.Count,
            MatchesDiscounted = discounted,
            Checks =
            [
                .. _rules.Select(rule =>
                {
                    var looked = examined.GetValueOrDefault(rule.Id);

                    return new CheckOutcome
                    {
                        Id = rule.Id,
                        Title = rule.Title,
                        Category = rule.Category,
                        FilesExamined = looked,

                        // Order matters. A rule that fired is reported as having found
                        // something even if other files timed out under it, and a rule that
                        // looked at nothing is never a pass however clean the run appeared.
                        State = fired.ContainsKey(rule.Id) ? CheckState.FoundIssues
                            : looked > 0 ? CheckState.Passed
                            : CheckState.NotChecked,
                    };
                }),
            ],
        };
    }

    /// <summary>
    /// The checks that examined nothing, and the languages present, in the reader's terms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Most of the catalogue carries no language filter, but a handful are written against the
    /// syntax of one language and cannot fire anywhere else. Somebody scanning a Go or PHP
    /// application therefore gets a smaller set of checks than the total implies, and until now
    /// the only trace of that was a row in the checks list reading "could not run" with no reason
    /// beside it, which reads as the scan having failed rather than as a fact about the code.
    /// </para>
    /// <para>
    /// <b>Counted from what actually ran, not from the catalogue's declarations.</b> A rule that
    /// examined no files is inapplicable whatever the reason, so this stays correct if a rule is
    /// ever scoped by something other than language. It claims only what it can prove: that these
    /// checks looked at nothing here. It does not assert why, because the engine does not know.
    /// </para>
    /// </remarks>
    private string? InapplicableChecks(
        ConcurrentDictionary<string, int> examined,
        IReadOnlyList<RecoveredFile> files)
    {
        var idle = _rules.Count(rule => examined.GetValueOrDefault(rule.Id) == 0);

        if (idle == 0 || files.Count == 0)
        {
            return null;
        }

        var languages = files
            .Select(file => file.Language)
            .Distinct()
            .Select(PlainName)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        // "written in" rather than "is", because one of the names is a phrase rather than a
        // language. "The code here is languages these checks do not name individually" is what
        // a Go or PHP project produced, which is the reader this sentence was added for.
        var written = languages.Count switch
        {
            0 => string.Empty,
            1 => $" The code here is written in {languages[0]}.",
            _ => $" The code here is written in {string.Join(", ", languages[..^1])} "
                 + $"and {languages[^1]}.",
        };

        return $"{idle} of the {_rules.Count} checks did not apply to any file in this "
               + $"application, so they did not run.{written} They are listed as not run rather "
               + "than as passed, because a check that examined nothing has not cleared anything.";
    }

    /// <summary>
    /// A language as somebody who does not write code would name it, or null when it is not
    /// program text and naming it would pad the sentence rather than inform it.
    /// </summary>
    private static string? PlainName(SourceLanguage language) => language switch
    {
        SourceLanguage.CSharp => "C#",
        SourceLanguage.JavaScript => "JavaScript",
        SourceLanguage.TypeScript => "TypeScript",
        SourceLanguage.Python => "Python",
        SourceLanguage.Java => "Java",
        SourceLanguage.Shell => "shell scripts",
        SourceLanguage.Other => "languages these checks do not name individually",
        _ => null,
    };

    /// <summary>
    /// Softens findings that sit in test and example files.
    /// </summary>
    /// <remarks>
    /// A SQL injection in a fixture is not shipped and does not deserve the same weight as one
    /// on a live path. Secrets are exempt from the softening: a credential committed to a test
    /// file is just as published as one in production code, and is scraped from public
    /// repositories exactly the same way.
    /// </remarks>
    private static Finding Adjust(Finding finding, RecoveredFile file)
    {
        if (finding.Category == FindingCategory.Secrets
            || !Heuristics.IsTestOrExampleFile(file.RelativePath)
            || finding.Severity == Severity.Info)
        {
            return finding;
        }

        return finding with
        {
            Severity = (Severity)((int)finding.Severity - 1),
            // A blocking claim must not rest on a fixture.
            IsBlocking = false,
            Description = finding.Description
                + " Severity is reduced because this file appears to be a test or example.",
        };
    }

    /// <summary>
    /// Collapses repeats of the same rule at the same place, then orders worst-first.
    /// </summary>
    private static List<Finding> Deduplicate(IEnumerable<Finding> findings) =>
        [.. findings
            // By place rather than by line, matching the rule's own test for the same thing.
            // Keyed on the line alone this folded a bundle's findings back into one after the
            // rule had correctly told them apart, since a minified file is all line 1.
            .GroupBy(f => (
                f.RuleId,
                f.FilePath,
                f.Line,
                Region: (f.Column ?? 0) / RuleContext.RegionWidth))
            .Select(group => group.First())
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ThenBy(f => f.FilePath, StringComparer.Ordinal)
            .ThenBy(f => f.Line)];
}
