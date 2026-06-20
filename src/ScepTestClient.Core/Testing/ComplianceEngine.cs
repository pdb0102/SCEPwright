using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Protocol;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

public sealed class ComplianceEngine {
    private static readonly ComplianceCheck[] Matrix =
    {
        new("forbidden algorithm (MD5)",      FaultKind.ForbiddenAlgorithm,   FailInfo.BadAlg,          "RFC 8894 §2.9"),
        new("corrupted CMS signature",        FaultKind.CorruptedSignature,   FailInfo.BadMessageCheck, "RFC 8894 §3.2"),
        new("signingTime skew (+2h)",         FaultKind.SkewedSigningTime,    FailInfo.BadTime,         "RFC 8894 §3.2.1"),
        new("wrong challenge password",       FaultKind.WrongChallenge,       FailInfo.None,            "RFC 8894 §3.2"),
        new("GetCert unknown serial",         FaultKind.UnknownCertId,        FailInfo.BadCertId,       "RFC 8894 §3.2"),
        new("malformed PKCS#10",              FaultKind.MalformedRequest,     FailInfo.BadRequest,      "RFC 8894 §3.2"),
        new("RenewalReq when not advertised", FaultKind.RenewalNotAdvertised, FailInfo.None,            "RFC 8894 §3.2"),
    };

    public TestReport RunFull(ScepClient client, X509Certificate2 ca_cert, ScepCapabilities caps) {
        TestReport report;
        Stopwatch total;

        report = new TestReport { ServerId = client.Server.Id, Mode = "full" };
        total = Stopwatch.StartNew();
        foreach (ComplianceCheck check in Matrix) {
            report.Results.Add(RunCheck(client, ca_cert, caps, check));
        }
        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    private CheckResult RunCheck(ScepClient client, X509Certificate2 ca_cert, ScepCapabilities caps, ComplianceCheck check) {
        Stopwatch sw;
        PkiStatus status;
        FailInfo got;

        sw = Stopwatch.StartNew();
        Execute(client, ca_cert, caps, check, out status, out got);
        sw.Stop();
        return Classify(check, status, got, sw.Elapsed);
    }

    private void Execute(ScepClient client, X509Certificate2 ca_cert, ScepCapabilities caps, ComplianceCheck check,
                         out PkiStatus status, out FailInfo got) {
        ScepResult<EnrollOutcome> result;
        ScepResult<X509Certificate2> cert_result;

        status = PkiStatus.Failure;
        got = FailInfo.None;

        if (check.Kind == FaultKind.UnknownCertId) {
            cert_result = client.GetCert(ca_cert.Subject, "00DEADBEEF");
            status = cert_result.IsOk ? PkiStatus.Success : PkiStatus.Failure;
            got = cert_result.IsOk ? FailInfo.None : ExtractFailInfo(cert_result.Error);
            return;
        }

        if (check.Kind == FaultKind.RenewalNotAdvertised) {
            // A RenewalReq needs an existing cert+key, so enroll first then renew with it.
            ExecuteRenewal(client, ca_cert, out status, out got);
            return;
        }

        switch (check.Kind) {
            case FaultKind.ForbiddenAlgorithm:
                result = SubmitEnroll(client, ca_cert, "MD5", null, null, MessageType.PkcsReq);
                break;
            case FaultKind.CorruptedSignature:
                result = SubmitEnroll(client, ca_cert, null, null, new FaultDirectives { CorruptSignature = true }, MessageType.PkcsReq);
                break;
            case FaultKind.SkewedSigningTime:
                result = SubmitEnroll(client, ca_cert, null, null, new FaultDirectives { SigningTimeSkew = System.TimeSpan.FromHours(2) }, MessageType.PkcsReq);
                break;
            case FaultKind.WrongChallenge:
                result = SubmitEnroll(client, ca_cert, null, "definitely-wrong-" + System.Guid.NewGuid().ToString("N"), null, MessageType.PkcsReq);
                break;
            case FaultKind.MalformedRequest:
                result = SubmitEnroll(client, ca_cert, null, null, new FaultDirectives { CorruptInnerContent = true }, MessageType.PkcsReq);
                break;
            default:
                return;
        }

        status = result.Value?.PkiStatus ?? PkiStatus.Failure;
        got = result.Value?.FailInfo ?? FailInfo.None;
    }

    // The builder requires a SignerCertificate+SignerKey for a RenewalReq, so a real renewal must
    // start from an issued cert: enroll once, then submit a proper RenewalReq signed by it. A server
    // that honors the renewal despite never advertising the Renewal cap is the "more lenient" finding.
    private static void ExecuteRenewal(ScepClient client, X509Certificate2 ca_cert, out PkiStatus status, out FailInfo got) {
        string subject;
        ScepRequestBuilder enroll_builder;
        PkiMessage enroll_message;
        IScepKey enroll_key;
        string enroll_error;
        ScepResult<EnrollOutcome> enroll_result;
        ScepRequestBuilder renew_builder;
        PkiMessage renew_message;
        IScepKey renew_key;
        string renew_error;
        ScepResult<EnrollOutcome> renew_result;

        status = PkiStatus.Failure;
        got = FailInfo.None;

        subject = "CN=renew-seed-" + System.Guid.NewGuid().ToString("N").Substring(0, 8);

        enroll_builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ca_cert)
            .MessageType(MessageType.PkcsReq)
            .Subject(subject)
            .KeySpec("rsa:2048");
        if (!enroll_builder.Build(out enroll_message, out enroll_key, out enroll_error)) {
            return;
        }
        enroll_result = client.SubmitPkiOperation(enroll_message, enroll_key, null);
        if (!enroll_result.IsOk || enroll_result.Value?.Certificate is null) {
            return;
        }

        renew_builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ca_cert)
            .MessageType(MessageType.RenewalReq)
            .Subject(subject)
            .KeySpec("rsa:2048")
            .SignerCertificate(enroll_result.Value.Certificate)
            .SignerKey(enroll_key);
        if (!renew_builder.Build(out renew_message, out renew_key, out renew_error)) {
            return;
        }
        renew_result = client.SubmitPkiOperation(renew_message, renew_key, null);
        status = renew_result.Value?.PkiStatus ?? PkiStatus.Failure;
        got = renew_result.Value?.FailInfo ?? FailInfo.None;
    }

    private static ScepResult<EnrollOutcome> SubmitEnroll(ScepClient client, X509Certificate2 ca_cert, string? digest,
                                                          string? challenge, FaultDirectives? faults, MessageType message_type) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;

        builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ca_cert)
            .MessageType(message_type)
            .Subject("CN=compliance-" + System.Guid.NewGuid().ToString("N").Substring(0, 8))
            .KeySpec("rsa:2048");
        if (digest != null) { builder.Digest(digest); }
        if (challenge != null) { builder.Challenge(challenge); }
        if (faults != null) { builder.AllowFaults(faults); }

        if (!builder.Build(out message, out subject_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return client.SubmitPkiOperation(message, subject_key, builder.Faults);
    }

    private static CheckResult Classify(ComplianceCheck check, PkiStatus status, FailInfo got, System.TimeSpan elapsed) {
        CheckOutcome outcome;
        string why;

        if (check.Expected == FailInfo.None) {
            // Expect a generic FAILURE (server-specific failInfo). Acceptance = the server rejected at all.
            if (status == PkiStatus.Failure) {
                outcome = CheckOutcome.Passed;
                why = $"server rejected as expected (failInfo {got})";
            } else {
                outcome = CheckOutcome.Finding;
                why = "server accepted a request the RFC lets it reject (more lenient than spec)";
            }
        } else if (status == PkiStatus.Failure && got == check.Expected) {
            outcome = CheckOutcome.Passed;
            why = $"got expected {check.Expected}";
        } else if (status == PkiStatus.Success) {
            outcome = CheckOutcome.Finding;
            why = $"expected {check.Expected}, but server SUCCEEDED (more lenient than RFC 8894)";
        } else {
            outcome = CheckOutcome.Failed;
            why = $"expected {check.Expected}, got {got} (status {status})";
        }
        return new CheckResult(check.Name, outcome, check.Expected, got, status, why, check.RfcReference, elapsed);
    }

    private static FailInfo ExtractFailInfo(string error) {
        // ScepClient.ProjectCert embeds the FailInfo enum name in its error message (e.g. "... failInfo BadCertId").
        if (error.Contains("BadCertId")) { return FailInfo.BadCertId; }
        if (error.Contains("BadMessageCheck")) { return FailInfo.BadMessageCheck; }
        if (error.Contains("BadRequest")) { return FailInfo.BadRequest; }
        if (error.Contains("BadTime")) { return FailInfo.BadTime; }
        if (error.Contains("BadAlg")) { return FailInfo.BadAlg; }
        return FailInfo.None;
    }
}
