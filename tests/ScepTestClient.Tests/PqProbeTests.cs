using System.Linq;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Testing;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqProbeTests {
    [Fact]
    public async Task Probe_includes_ml_dsa_row() {
        FakeScepServer server;
        ScepClient client;
        TestReport report;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientFor(server);
            report = new TestEngine().RunProbe(client);

            // Built-in provider supports tier A, so the PQ row must exist and must NOT be Skipped.
            Assert.Contains(report.Results, r => r.Name.Contains("ML-DSA"));
            Assert.DoesNotContain(report.Results, r => r.Name.Contains("ML-DSA") && r.Outcome == CheckOutcome.Skipped);
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
}
