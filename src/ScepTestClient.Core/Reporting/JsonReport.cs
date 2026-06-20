using System.Linq;
using System.Text.Json;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Core.Reporting;

public static class JsonReport {
    public static string Emit(TestReport report) {
        object payload;

        payload = new {
            serverId = report.ServerId,
            mode = report.Mode,
            totals = new { passed = report.Passed, failed = report.Failed, skipped = report.Skipped, findings = report.Findings },
            totalElapsedMs = (long)report.TotalElapsed.TotalMilliseconds,
            results = report.Results.Select(r => new {
                name = r.Name,
                outcome = r.Outcome.ToString(),
                expected = r.Expected.ToString(),
                got = r.Got.ToString(),
                status = r.GotStatus.ToString(),
                why = r.Why,
                rfc = r.RfcReference,
                elapsedMs = (long)r.Elapsed.TotalMilliseconds,
            }).ToArray(),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }
}
