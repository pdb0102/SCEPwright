using System.Collections.Generic;
using System.Linq;

namespace ScepTestClient.Core.Testing;

public sealed class TestReport {
    public string ServerId { get; init; } = string.Empty;
    public string Mode { get; init; } = string.Empty;
    public List<CheckResult> Results { get; } = new();
    public System.TimeSpan TotalElapsed { get; set; }

    public int Passed => Results.Count(r => r.Outcome == CheckOutcome.Passed);
    public int Failed => Results.Count(r => r.Outcome == CheckOutcome.Failed);
    public int Skipped => Results.Count(r => r.Outcome == CheckOutcome.Skipped);
    public int Findings => Results.Count(r => r.Outcome == CheckOutcome.Finding);
}
