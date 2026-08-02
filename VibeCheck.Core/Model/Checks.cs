namespace VibeCheck.Core.Model;

/// <summary>How one check ended up. Three states, never two.</summary>
/// <remarks>
/// A report that shows only failures reads as a list of accusations and gives the reader no
/// sense of how much was examined and found sound. Showing passes fixes that, but it has to be
/// careful about what it claims: a check that never ran against anything has not passed, it has
/// not happened, and rendering those two the same way is precisely how a scan that read almost
/// nothing ends up looking clean. That mistake has been made three times in this codebase in
/// three different subsystems, which is why the third state is not optional.
/// </remarks>
public enum CheckState
{
    /// <summary>Ran against at least one file and found nothing.</summary>
    Passed,

    /// <summary>Ran and found something.</summary>
    FoundIssues,

    /// <summary>Never ran, because nothing it applies to was recovered.</summary>
    NotChecked,
}

/// <summary>One check and what became of it.</summary>
public sealed record CheckOutcome
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public required FindingCategory Category { get; init; }

    public required CheckState State { get; init; }

    /// <summary>
    /// How many files it looked at, which is what a pass is worth. A check that examined one
    /// file and a check that examined four hundred are not the same reassurance, and a reader
    /// deciding how much weight to give a green tick is entitled to the difference.
    /// </summary>
    public int FilesExamined { get; init; }
}

/// <summary>The check list as a whole, counted for display.</summary>
public sealed record CheckSummary
{
    public IReadOnlyList<CheckOutcome> Checks { get; init; } = [];

    public int Passed => Checks.Count(c => c.State == CheckState.Passed);

    public int FoundIssues => Checks.Count(c => c.State == CheckState.FoundIssues);

    public int NotChecked => Checks.Count(c => c.State == CheckState.NotChecked);

    /// <summary>
    /// One line stating all three counts together, because any two of them without the third
    /// is a misleading summary in one direction or the other.
    /// </summary>
    public string Describe() =>
        $"{Passed} check{(Passed == 1 ? "" : "s")} passed, "
        + $"{FoundIssues} found something, "
        + $"{NotChecked} could not run against this application.";
}
