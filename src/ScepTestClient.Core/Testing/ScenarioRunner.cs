using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

public static class ScenarioRunner {
    public static bool Parse(string json, out ScenarioFile scenario, out string error) {
        ScenarioFile? parsed;

        scenario = null!;
        error = string.Empty;
        try {
            parsed = JsonSerializer.Deserialize<ScenarioFile>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        } catch (System.Exception ex) {
            error = ex.Message;
            return false;
        }
        if (parsed == null) { error = "empty scenario"; return false; }
        scenario = parsed;
        return true;
    }

    public static TestReport Run(ScepClient client, ScenarioFile scenario, X509Certificate2 ca_cert) {
        TestReport report;
        Stopwatch total;

        report = new TestReport { ServerId = client.Server.Id, Mode = "scenario" };
        total = Stopwatch.StartNew();
        foreach (ScenarioStep step in scenario.Steps) {
            report.Results.Add(RunStep(client, ca_cert, step));
        }
        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    private static CheckResult RunStep(ScepClient client, X509Certificate2 ca_cert, ScenarioStep step) {
        Stopwatch sw;
        PkiStatus status;
        FailInfo got;
        bool matched;
        string why;

        sw = Stopwatch.StartNew();
        ExecuteStep(client, ca_cert, step, out status, out got);
        sw.Stop();

        matched = Matches(step.Expect, status, got);
        why = matched ? $"matched expect '{step.Expect}'" : $"expected '{step.Expect}', got status {status} failInfo {got}";
        return new CheckResult(step.Name, matched ? CheckOutcome.Passed : CheckOutcome.Failed,
            ExpectToFailInfo(step.Expect), got, status, why, "scenario", sw.Elapsed);
    }

    private static void ExecuteStep(ScepClient client, X509Certificate2 ca_cert, ScenarioStep step, out PkiStatus status, out FailInfo got) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey key;
        string error;
        ScepResult<EnrollOutcome> result;

        status = PkiStatus.Failure;
        got = FailInfo.None;
        switch (step.Run.ToLowerInvariant()) {
            case "getcacaps":
                status = client.GetCaCaps().IsOk ? PkiStatus.Success : PkiStatus.Failure;
                return;
            case "enroll":
            case "probe":
                builder = ScepRequestBuilder.For(client.Crypto)
                    .CaCertificate(ca_cert)
                    .MessageType(MessageType.PkcsReq)
                    .Subject(step.Args.TryGetValue("subject", out string? subj) ? subj : "CN=scenario")
                    .KeySpec("rsa:2048");
                if (step.Args.TryGetValue("digest", out string? digest)) { builder.Digest(digest); }
                if (step.Args.TryGetValue("cipher", out string? cipher)) { builder.Cipher(cipher); }
                if (step.Args.TryGetValue("challenge", out string? ch)) { builder.Challenge(ch); }
                if (!builder.Build(out message, out key, out error)) { return; }
                result = client.SubmitPkiOperation(message, key, builder.Faults);
                status = result.Value?.PkiStatus ?? PkiStatus.Failure;
                got = result.Value?.FailInfo ?? FailInfo.None;
                return;
            default:
                return;
        }
    }

    private static bool Matches(string? expect, PkiStatus status, FailInfo got) {
        switch ((expect ?? "pass").ToLowerInvariant()) {
            case "pass": return status == PkiStatus.Success;
            case "fail": return status != PkiStatus.Success;
            default: return status != PkiStatus.Success && got == ExpectToFailInfo(expect);
        }
    }

    private static FailInfo ExpectToFailInfo(string? expect) {
        switch ((expect ?? string.Empty).ToLowerInvariant()) {
            case "badalg": return FailInfo.BadAlg;
            case "badmessagecheck": return FailInfo.BadMessageCheck;
            case "badtime": return FailInfo.BadTime;
            case "badrequest": return FailInfo.BadRequest;
            case "badcertid": return FailInfo.BadCertId;
            default: return FailInfo.None;
        }
    }
}
