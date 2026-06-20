using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Testing;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class JamfSimulatorTests {
    [Fact]
    public async Task Pending_ExceedsMaxWait_TimesOut() {
        FakeScepServer server;
        ScepClient client;
        IScepCrypto crypto;
        EnrollRequest request;
        JamfResult result;

        server = await FakeScepServer.StartAsync();
        try {
            server.Ca.PendingMode = true;
            client = BuildClientFor(server, out crypto);
            request = BuildEnrollRequest(crypto, server.Ca.CertificateBcl);
            result = JamfSimulator.Run(client, request, server.Ca.CertificateBcl.Subject,
                System.TimeSpan.FromMilliseconds(60), System.TimeSpan.FromMilliseconds(20));
            Assert.True(result.TimedOut);
            Assert.True(result.PollCount >= 1);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Inline_Issue_DoesNotTimeOut() {
        FakeScepServer server;
        ScepClient client;
        IScepCrypto crypto;
        EnrollRequest request;
        JamfResult result;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientFor(server, out crypto);
            request = BuildEnrollRequest(crypto, server.Ca.CertificateBcl);
            result = JamfSimulator.Run(client, request, server.Ca.CertificateBcl.Subject,
                System.TimeSpan.FromSeconds(2), System.TimeSpan.FromMilliseconds(20));
            Assert.False(result.TimedOut);
            Assert.NotNull(result.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepClient BuildClientFor(FakeScepServer server, out IScepCrypto crypto) {
        BouncyCastleScepCrypto bc_crypto;
        ScepClient client;

        bc_crypto = new BouncyCastleScepCrypto();
        crypto = bc_crypto;
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, bc_crypto, handler: null, out client, out _);
        return client;
    }

    private static EnrollRequest BuildEnrollRequest(IScepCrypto crypto, System.Security.Cryptography.X509Certificates.X509Certificate2 ca_cert) {
        KeySpec spec;
        IScepKey key;

        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        return new EnrollRequest { Subject = "CN=jamf-client", Key = key, ChallengePassword = "pw", CaCertificate = ca_cert };
    }
}
