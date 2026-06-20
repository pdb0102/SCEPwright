using System.Xml.Linq;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Core.Reporting;

public static class JUnitReport {
    public static string Emit(TestReport report) {
        XElement suite;

        suite = new XElement("testsuite",
            new XAttribute("name", $"scep-{report.ServerId}-{report.Mode}"),
            new XAttribute("tests", report.Results.Count),
            new XAttribute("failures", report.Failed),
            new XAttribute("skipped", report.Skipped),
            new XAttribute("time", report.TotalElapsed.TotalSeconds));

        foreach (CheckResult result in report.Results) {
            XElement test_case;

            test_case = new XElement("testcase",
                new XAttribute("name", result.Name),
                new XAttribute("classname", $"scep.{report.Mode}"),
                new XAttribute("time", result.Elapsed.TotalSeconds));

            if (result.Outcome == CheckOutcome.Failed) {
                test_case.Add(new XElement("failure",
                    new XAttribute("message", $"expected {result.Expected}, got {result.Got}"),
                    result.Why + " (" + result.RfcReference + ")"));
            } else if (result.Outcome == CheckOutcome.Skipped) {
                test_case.Add(new XElement("skipped", new XAttribute("message", result.Why)));
            } else if (result.Outcome == CheckOutcome.Finding) {
                test_case.Add(new XElement("system-out", "FINDING: " + result.Why + " (" + result.RfcReference + ")"));
            }
            suite.Add(test_case);
        }

        return new XDocument(new XElement("testsuites", suite)).ToString();
    }
}
