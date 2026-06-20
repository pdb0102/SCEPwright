using System.Text;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Core.Reporting;

public static class MarkdownReport {
    public static string Emit(TestReport report) {
        StringBuilder sb;

        sb = new StringBuilder();
        sb.AppendLine($"# SCEP test run — {report.ServerId} — {report.Mode}");
        sb.AppendLine();
        sb.AppendLine($"PASSED {report.Passed} · FAILED {report.Failed} · SKIPPED {report.Skipped} · FINDINGS {report.Findings} · {report.TotalElapsed.TotalSeconds:0.0}s");
        sb.AppendLine();
        sb.AppendLine("| Check | Outcome | Expected | Got | Why |");
        sb.AppendLine("|---|---|---|---|---|");
        foreach (CheckResult r in report.Results) {
            sb.AppendLine($"| {r.Name} | {r.Outcome} | {r.Expected} | {r.Got} | {r.Why} |");
        }
        return sb.ToString();
    }
}
