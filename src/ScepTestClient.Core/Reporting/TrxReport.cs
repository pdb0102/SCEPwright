using System.Xml.Linq;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Core.Reporting;

public static class TrxReport {
    private static readonly XNamespace Ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";

    public static string Emit(TestReport report) {
        XElement results;
        XElement run;

        results = new XElement(Ns + "Results");
        foreach (CheckResult result in report.Results) {
            results.Add(new XElement(Ns + "UnitTestResult",
                new XAttribute("testName", result.Name),
                new XAttribute("outcome", result.Outcome == CheckOutcome.Failed ? "Failed" : "Passed"),
                new XAttribute("duration", result.Elapsed.ToString()),
                new XElement(Ns + "Output", new XElement(Ns + "StdOut", result.Why))));
        }

        run = new XElement(Ns + "TestRun",
            new XAttribute("name", $"scep-{report.ServerId}-{report.Mode}"),
            results);
        return new XDocument(run).ToString();
    }
}
