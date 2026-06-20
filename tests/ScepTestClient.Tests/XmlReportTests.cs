using System.Xml.Linq;
using ScepTestClient.Core.Reporting;
using ScepTestClient.Core.Testing;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Tests;

public sealed class XmlReportTests {
    private static TestReport Sample() {
        TestReport report;

        report = new TestReport { ServerId = "testhost", Mode = "full" };
        report.Results.Add(new CheckResult("ok check", CheckOutcome.Passed, FailInfo.None, FailInfo.None, PkiStatus.Failure, "got expected", "RFC 8894", System.TimeSpan.FromMilliseconds(10)));
        report.Results.Add(new CheckResult("bad check", CheckOutcome.Failed, FailInfo.BadTime, FailInfo.None, PkiStatus.Success, "server accepted skew", "RFC 8894 §3.2.1", System.TimeSpan.FromMilliseconds(20)));
        return report;
    }

    [Fact]
    public void JUnit_IsWellFormed_WithFailure() {
        string xml;
        XDocument doc;

        xml = JUnitReport.Emit(Sample());
        doc = XDocument.Parse(xml);
        Assert.NotNull(doc.Root);
        Assert.Contains("bad check", xml);
        Assert.Contains("failure", xml);
    }

    [Fact]
    public void Trx_IsWellFormed() {
        string xml;

        xml = TrxReport.Emit(Sample());
        Assert.NotNull(XDocument.Parse(xml).Root);
        Assert.Contains("Failed", xml);
    }
}
