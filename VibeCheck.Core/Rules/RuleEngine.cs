using System.Collections.Concurrent;

using VibeCheck.Core.Model;
using VibeCheck.Core.Recovery;

namespace VibeCheck.Core.Rules;

/// <summary>What the rule pass produced, including anything it could not complete.</summary>
public sealed record RuleEngineResult
{
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>
    /// Checks that did not finish, so the report can distinguish "nothing found" from
    /// "not looked at".
    /// </summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    public int FilesAnalysed { get; init; }
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

                try
                {
                    foreach (var finding in rule.Examine(context))
                    {
                        findings.Add(Adjust(finding, file));
                    }
                }
                catch (RuleTimeoutException)
                {
                    // Recorded rather than swallowed: an unfinished check is not a clean one.
                    limitations.TryAdd(
                        $"Check {rule.Id} did not complete on {file.RelativePath} and was skipped.",
                        0);
                }
            }

            progress?.Report(Interlocked.Increment(ref completed));
        });

        return new RuleEngineResult
        {
            Findings = Deduplicate(findings),
            Limitations = [.. limitations.Keys.Order(StringComparer.Ordinal)],
            FilesAnalysed = files.Count,
        };
    }

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
            .GroupBy(f => (f.RuleId, f.FilePath, f.Line))
            .Select(group => group.First())
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ThenBy(f => f.FilePath, StringComparer.Ordinal)
            .ThenBy(f => f.Line)];
}
