using System.Text.Json;
using ScepTestClient.Core.Reporting;
using ScepTestClient.Core.Testing;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Tests;

public sealed class TextReportTests {
    private static TestReport Sample() {
        TestReport report;

        report = new TestReport { ServerId = "testhost", Mode = "full" };
        report.Results.Add(new CheckResult("ok", CheckOutcome.Passed, FailInfo.BadAlg, FailInfo.BadAlg, PkiStatus.Failure, "got expected BadAlg", "RFC 8894 §2.9", System.TimeSpan.FromMilliseconds(5)));
        report.Results.Add(new CheckResult("skew", CheckOutcome.Failed, FailInfo.BadTime, FailInfo.None, PkiStatus.Success, "server accepted +2h skew", "RFC 8894 §3.2.1", System.TimeSpan.FromMilliseconds(7)));
        report.Results.Add(new CheckResult("lenient", CheckOutcome.Finding, FailInfo.None, FailInfo.None, PkiStatus.Success, "SHA-256 works though only SHA-1 advertised", "under-advertised", System.TimeSpan.FromMilliseconds(3)));
        return report;
    }

    [Fact]
    public void Json_HasTotalsAndResults() {
        string json;
        JsonDocument doc;

        json = JsonReport.Emit(Sample());
        doc = JsonDocument.Parse(json);
        Assert.Equal(1, doc.RootElement.GetProperty("totals").GetProperty("failed").GetInt32());
        Assert.Equal("testhost", doc.RootElement.GetProperty("serverId").GetString());
    }

    [Fact]
    public void Console_ShowsFailedAndFindings() {
        string text;

        text = ConsoleSummary.Format(Sample());
        Assert.Contains("FAILED   1", text);
        Assert.Contains("FINDINGS 1", text);
        Assert.Contains("expected BadTime, got None", text);
    }

    [Fact]
    public void Markdown_HasTable() {
        string md;

        md = MarkdownReport.Emit(Sample());
        Assert.Contains("| Check | Outcome", md);
    }
}
