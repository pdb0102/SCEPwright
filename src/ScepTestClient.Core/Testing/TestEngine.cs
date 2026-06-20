using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

// Two smoke modes on top of the compliance matrix:
//  - RunLifecycle: the happy-path round-trip a real client makes (caps -> cacert -> enroll ->
//    poll-if-pending -> renew -> CRL); a step is Skipped only when its prerequisite failed.
//  - RunProbe: deliberately steps BEYOND the advertised caps (SHA-256, POST, GetNextCACert) and
//    reports PASSED (worked and advertised) / FINDING (worked but never advertised) / FAILED.
//  - RunFull: delegates to ComplianceEngine.
public sealed class TestEngine {
    public TestReport RunFull(ScepClient client, X509Certificate2 ca_cert, ScepCapabilities caps) {
        return new ComplianceEngine().RunFull(client, ca_cert, caps);
    }

    public TestReport RunLifecycle(ScepClient client, CertStore store, UseRecordLog log) {
        TestReport report;
        Stopwatch total;
        bool caps_ok;
        bool ca_ok;
        X509Certificate2? ca_cert;
        bool enroll_ok;
        string? cert_id;
        bool pending;

        report = new TestReport { ServerId = client.Server.Id, Mode = "lifecycle" };
        total = Stopwatch.StartNew();

        caps_ok = Step(report, "GetCACaps", () => client.GetCaCaps().IsOk);

        ca_cert = null;
        ca_ok = StepCaCert(report, client, out ca_cert);

        if (!ca_ok || ca_cert == null) {
            Skip(report, "enroll", "GetCACert failed");
            Skip(report, "renew", "enroll skipped");
            Skip(report, "GetCRL", "GetCACert failed");
            total.Stop();
            report.TotalElapsed = total.Elapsed;
            return report;
        }

        cert_id = null;
        pending = false;
        enroll_ok = StepEnroll(report, client, ca_cert, store, log, out cert_id, out pending);

        // poll-if-pending: only attempt a poll when the enroll actually came back PENDING.
        if (pending) {
            Step(report, "poll", () => client.Poll(ca_cert!.Subject, "CN=lifecycle", System.Guid.NewGuid().ToString("N")).Status != ScepClientResult.NetworkError);
        }

        if (!enroll_ok || cert_id == null) {
            Skip(report, "renew", "enroll failed");
        } else {
            Step(report, "renew", () => client.RenewCertificate(cert_id!, store, log).IsOk);
        }

        Step(report, "GetCRL", () => client.GetCrl(ca_cert!.Subject, "01").IsOk);

        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    public TestReport RunProbe(ScepClient client) {
        TestReport report;
        Stopwatch total;
        ScepCapabilities caps;
        ScepResult<ScepCapabilities> caps_result;

        report = new TestReport { ServerId = client.Server.Id, Mode = "probe" };
        total = Stopwatch.StartNew();

        caps_result = client.GetCaCaps();
        caps = caps_result.IsOk ? caps_result.Value : ScepCapabilities.Parse(string.Empty);

        ProbeDigest(report, client, caps);
        ProbePost(report, client, caps);
        ProbeGetNextCa(report, client, caps);
        ProbePq(report, client);

        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    // -------------------------------------------------------------------------
    // Lifecycle helpers
    // -------------------------------------------------------------------------

    private static bool StepCaCert(TestReport report, ScepClient client, out X509Certificate2? ca_cert) {
        Stopwatch sw;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;
        bool ok;

        ca_cert = null;
        sw = Stopwatch.StartNew();
        try {
            result = client.GetCaCert();
            ok = result.IsOk && result.Value.Count > 0;
            if (ok) { ca_cert = result.Value[0]; }
        } catch (System.Exception) {
            ok = false;
        }
        sw.Stop();
        Record(report, "GetCACert", ok, ok ? "ok" : "step failed", sw.Elapsed);
        return ok;
    }

    private static bool StepEnroll(TestReport report, ScepClient client, X509Certificate2 ca_cert, CertStore store, UseRecordLog log,
                                   out string? cert_id, out bool pending) {
        Stopwatch sw;
        KeySpec spec;
        IScepKey key;
        string key_error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> result;
        bool ok;
        string why;

        cert_id = null;
        pending = false;

        sw = Stopwatch.StartNew();
        if (!KeySpec.Parse("rsa:2048", out spec, out key_error)) {
            sw.Stop();
            Record(report, "enroll", false, "key spec parse failed: " + key_error, sw.Elapsed);
            return false;
        }
        if (!client.Crypto.GenerateKey(spec, out key, out key_error)) {
            sw.Stop();
            Record(report, "enroll", false, "key generation failed: " + key_error, sw.Elapsed);
            return false;
        }

        request = new EnrollRequest {
            Subject = "CN=lifecycle-" + System.Guid.NewGuid().ToString("N").Substring(0, 8),
            Key = key,
            CaCertificate = ca_cert,
        };

        try {
            result = client.GetNewCertificate(request, store, log);
        } catch (System.Exception ex) {
            sw.Stop();
            Record(report, "enroll", false, "enroll threw: " + ex.Message, sw.Elapsed);
            return false;
        }
        sw.Stop();

        pending = result.Status == ScepClientResult.Pending;
        ok = result.IsOk && result.Value?.Certificate != null;
        if (ok) { cert_id = result.Value!.Certificate!.Thumbprint.ToLowerInvariant(); }
        why = ok ? "issued" : (pending ? "pending" : "enroll failed: " + result.Error);
        Record(report, "enroll", ok, why, sw.Elapsed);
        return ok;
    }

    // -------------------------------------------------------------------------
    // Probe helpers
    // -------------------------------------------------------------------------

    private static void ProbeDigest(TestReport report, ScepClient client, ScepCapabilities caps) {
        Stopwatch sw;
        bool worked;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        sw = Stopwatch.StartNew();
        advertised = caps.Sha256;
        worked = false;
        try {
            ca_result = ResolveCaCert(client);
            if (ca_result.IsOk) {
                worked = SubmitEnrollWithKeySpec(client, ca_result.Value, "rsa:2048", "SHA-256");
            }
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (!worked) {
            outcome = CheckOutcome.Failed;
            why = "SHA-256 enrollment did not succeed";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "SHA-256 worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "SHA-256 worked but the server never advertised it";
        }
        report.Results.Add(new CheckResult("probe SHA-256 digest", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §3.5.2", sw.Elapsed));
    }

    private static void ProbePost(TestReport report, ScepClient client, ScepCapabilities caps) {
        Stopwatch sw;
        bool worked;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        sw = Stopwatch.StartNew();
        advertised = caps.PostPkiOperation;
        worked = false;
        // The client posts when Server.PreferPost is set; if it is not, we cannot exercise POST here.
        try {
            if (client.Server.PreferPost) {
                ca_result = ResolveCaCert(client);
                if (ca_result.IsOk) {
                    worked = SubmitEnrollWithKeySpec(client, ca_result.Value, "rsa:2048", "SHA-256");
                }
            }
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (!client.Server.PreferPost) {
            outcome = CheckOutcome.Skipped;
            why = "client not configured to POST (Server.PreferPost is false)";
        } else if (!worked) {
            outcome = CheckOutcome.Failed;
            why = "POSTPKIOperation enrollment did not succeed";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "POST worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "POST worked but the server never advertised POSTPKIOperation";
        }
        report.Results.Add(new CheckResult("probe POSTPKIOperation", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §4.1", sw.Elapsed));
    }

    private static void ProbeGetNextCa(TestReport report, ScepClient client, ScepCapabilities caps) {
        Stopwatch sw;
        bool worked;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;

        sw = Stopwatch.StartNew();
        advertised = caps.GetNextCaCert;
        worked = false;
        try {
            result = client.GetNextCaCert();
            worked = result.IsOk && result.Value.Count > 0;
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (!worked) {
            outcome = CheckOutcome.Failed;
            why = advertised ? "GetNextCACert advertised but did not return a certificate" : "GetNextCACert not supported";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "GetNextCACert worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "GetNextCACert worked but the server never advertised it";
        }
        report.Results.Add(new CheckResult("probe GetNextCACert", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §4.6", sw.Elapsed));
    }

    // GetCACaps has no PQ keyword, so any ML-DSA success is a FINDING (PQ-capable / under-advertised
    // CA); a failure against a classical-only CA is the expected FAILED. Wrapped so it never throws.
    private static void ProbePq(TestReport report, ScepClient client) {
        Stopwatch sw;
        bool worked;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        if (!client.Crypto.Capabilities.PqTiers.TierA) {
            report.Results.Add(new CheckResult("probe ML-DSA enrollment", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "loaded provider does not implement PQ tier A", "spec §14 (empirical PQ probe)", System.TimeSpan.Zero));
            return;
        }

        sw = Stopwatch.StartNew();
        worked = false;
        try {
            ca_result = ResolveCaCert(client);
            if (ca_result.IsOk) {
                worked = SubmitEnrollWithKeySpec(client, ca_result.Value, "ml-dsa:65", "SHA-256");
            }
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (worked) {
            outcome = CheckOutcome.Finding;
            why = "ML-DSA enrollment succeeded though GetCACaps advertises no PQ capability (under-advertised / PQ-capable CA)";
        } else {
            outcome = CheckOutcome.Failed;
            why = "ML-DSA enrollment was not accepted (expected against a classical-only CA)";
        }
        report.Results.Add(new CheckResult("probe ML-DSA enrollment", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "spec §14 (empirical PQ probe)", sw.Elapsed));
    }

    private static ScepResult<X509Certificate2> ResolveCaCert(ScepClient client) {
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;

        result = client.GetCaCert();
        if (!result.IsOk || result.Value.Count == 0) {
            return ScepResult<X509Certificate2>.Fail(result.IsOk ? ScepClientResult.ServerFailure : result.Status,
                result.IsOk ? "server returned no CA certificate" : result.Error);
        }
        return ScepResult<X509Certificate2>.Ok(result.Value[0]);
    }

    private static bool SubmitEnrollWithKeySpec(ScepClient client, X509Certificate2 ca_cert, string key_spec, string digest) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        ScepResult<EnrollOutcome> result;

        builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ca_cert)
            .MessageType(MessageType.PkcsReq)
            .Subject("CN=probe-" + System.Guid.NewGuid().ToString("N").Substring(0, 8))
            .KeySpec(key_spec)
            .Digest(digest);
        if (!builder.Build(out message, out subject_key, out error)) {
            return false;
        }
        result = client.SubmitPkiOperation(message, subject_key, null);
        return result.IsOk && result.Value?.Certificate != null;
    }

    // -------------------------------------------------------------------------
    // Generic step recording
    // -------------------------------------------------------------------------

    private static bool Step(TestReport report, string name, System.Func<bool> action) {
        Stopwatch sw;
        bool ok;

        sw = Stopwatch.StartNew();
        try {
            ok = action();
        } catch (System.Exception) {
            ok = false;
        }
        sw.Stop();
        Record(report, name, ok, ok ? "ok" : "step failed", sw.Elapsed);
        return ok;
    }

    private static void Record(TestReport report, string name, bool ok, string why, System.TimeSpan elapsed) {
        report.Results.Add(new CheckResult(name, ok ? CheckOutcome.Passed : CheckOutcome.Failed,
            FailInfo.None, FailInfo.None, ok ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894", elapsed));
    }

    private static void Skip(TestReport report, string name, string why) {
        report.Results.Add(new CheckResult(name, CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
            PkiStatus.Failure, why, "RFC 8894", System.TimeSpan.Zero));
    }
}
