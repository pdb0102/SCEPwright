using System.Text;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Core.Reporting;

public static class ConsoleSummary {
    public static string Format(TestReport report) {
        StringBuilder sb;

        sb = new StringBuilder();
        sb.AppendLine($"SCEP test run — {report.ServerId} — {report.Mode}          {report.TotalElapsed.TotalSeconds:0.0}s");
        sb.AppendLine($"  PASSED   {report.Passed}");
        sb.AppendLine($"  FAILED   {report.Failed}");
        sb.AppendLine($"  SKIPPED  {report.Skipped}");
        sb.AppendLine($"  FINDINGS {report.Findings}");

        if (report.Failed > 0) {
            sb.AppendLine();
            sb.AppendLine("FAILED:");
            foreach (CheckResult r in report.Results) {
                if (r.Outcome == CheckOutcome.Failed) {
                    sb.AppendLine($"  ✗ {r.Name} → expected {r.Expected}, got {r.Got}");
                    sb.AppendLine($"      {r.Why}  ({r.RfcReference})");
                }
            }
        }
        if (report.Findings > 0) {
            sb.AppendLine();
            sb.AppendLine("FINDINGS:");
            foreach (CheckResult r in report.Results) {
                if (r.Outcome == CheckOutcome.Finding) {
                    sb.AppendLine($"  • {r.Name}: {r.Why}");
                }
            }
        }
        return sb.ToString();
    }
}
