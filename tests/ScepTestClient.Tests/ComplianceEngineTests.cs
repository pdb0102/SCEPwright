using System.Linq;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Testing;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class ComplianceEngineTests {
    [Fact]
    public async Task RunFull_ProducesExpectedOutcomes() {
        FakeScepServer server;
        ScepClient client;
        ScepCapabilities caps;
        ComplianceEngine engine;
        TestReport report;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            engine = new ComplianceEngine();
            report = engine.RunFull(client, server.Ca.CertificateBcl, caps);

            Assert.Equal("full", report.Mode);
            // The five well-defined failInfo rows pass against the fake:
            Assert.Equal(CheckOutcome.Passed, Find(report, "forbidden algorithm (MD5)").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "corrupted CMS signature").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "signingTime skew (+2h)").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "GetCert unknown serial").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "malformed PKCS#10").Outcome);
            // The fake handles renewal though caps omit Renewal -> a finding, not a failure.
            Assert.Equal(CheckOutcome.Finding, Find(report, "RenewalReq when not advertised").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    private static CheckResult Find(TestReport report, string name) =>
        report.Results.First(r => r.Name == name);

    private static ScepClient BuildClientFor(FakeScepServer server) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }
}
