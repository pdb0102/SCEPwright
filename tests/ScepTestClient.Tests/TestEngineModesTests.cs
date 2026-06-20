using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.Core.Testing;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class TestEngineModesTests {
    [Fact]
    public async Task Lifecycle_AllStepsRun_MostlyPassed() {
        FakeScepServer server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestEngine engine;
        TestReport report;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientWithStore(server, out store, out log);
            engine = new TestEngine();
            report = engine.RunLifecycle(client, store, log);

            Assert.Equal("lifecycle", report.Mode);
            Assert.Contains(report.Results, r => r.Name == "GetCACaps" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "GetCACert" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Passed);
            // enroll succeeded, so renew must run (not Skipped) and GetCRL must run.
            Assert.DoesNotContain(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Skipped);
            Assert.Contains(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "GetCRL" && r.Outcome == CheckOutcome.Passed);
            // Mostly PASSED against the fake (no failures expected).
            Assert.Equal(0, report.Failed);
            Assert.Equal(0, report.Skipped);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public void Lifecycle_SkipsDownstream_WhenCaCertFails() {
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        // Point at an unreachable endpoint so GetCACaps/GetCACert fail; downstream steps must Skip.
        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "dead", Url = new Uri("http://127.0.0.1:1/scep"), PreferPost = true }, crypto, handler: null, out client, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        report = new TestEngine().RunLifecycle(client, store, log);

        Assert.Contains(report.Results, r => r.Name == "GetCACert" && r.Outcome == CheckOutcome.Failed);
        Assert.Contains(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Skipped);
        Assert.Contains(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Skipped);
        Assert.Contains(report.Results, r => r.Name == "GetCRL" && r.Outcome == CheckOutcome.Skipped);
    }

    [Fact]
    public async Task Probe_Sha256_And_Post_Work() {
        FakeScepServer server;
        ScepClient client;
        TestReport report;
        CheckResult sha256;
        CheckResult post;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientFor(server);
            report = new TestEngine().RunProbe(client);

            Assert.Equal("probe", report.Mode);

            sha256 = report.Results.First(r => r.Name.Contains("SHA-256"));
            // The fake advertises SHA-256, so a working SHA-256 enroll is PASSED.
            Assert.Equal(CheckOutcome.Passed, sha256.Outcome);

            post = report.Results.First(r => r.Name.Contains("POST"));
            // The fake advertises POSTPKIOperation and the client posts -> PASSED.
            Assert.Equal(CheckOutcome.Passed, post.Outcome);

            // The fake's GET handler does not know GetNextCACert -> FAILED, but it must not crash.
            Assert.Contains(report.Results, r => r.Name.Contains("GetNextCACert"));
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepClient BuildClientFor(FakeScepServer server) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }

    private static ScepClient BuildClientWithStore(FakeScepServer server, out CertStore store, out UseRecordLog log) {
        string root;
        ScepClient client;

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);
        client = BuildClientFor(server);
        return client;
    }
}
