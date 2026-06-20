using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class RenewalTests {
    private static ScepClient MakeClient(FakeScepServer server, BouncyCastleScepCrypto crypto) {
        ScepClient client;
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }

    [Theory]
    [InlineData(RenewalVariant.Proper)]
    [InlineData(RenewalVariant.ReenrollSameSubject)]
    [InlineData(RenewalVariant.RenewalShapedPkcsReq)]
    [InlineData(RenewalVariant.SameKey)]
    public async Task Renews_and_returns_a_certificate(RenewalVariant variant) {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey existing_key;
        X509Certificate2 existing_cert;
        ScepClient client;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out existing_key, out _);
        existing_cert = new X509Certificate2(server.Ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

        client = MakeClient(server, crypto);
        request = new RenewRequest {
            Subject = "CN=poodle",
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = variant,
            ChallengePassword = "pw",
            CaCertificate = server.Ca.CertificateBcl,
        };

        result = await client.RenewAsync(request);
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
    }

    [Fact]
    public void Expired_variant_is_rejected_sync() {
        // The blocking GetResult below only awaits the in-memory test harness (server startup),
        // not a SCEP network call — client.Renew(request) itself runs the genuine sync path.
#pragma warning disable xUnit1031
        Task.Run(async () => {
            await using FakeScepServer server = await FakeScepServer.StartAsync();
            BouncyCastleScepCrypto crypto;
            KeySpec spec;
            IScepKey existing_key;
            X509Certificate2 expired_cert;
            ScepClient client;
            RenewRequest request;
            ScepResult<EnrollOutcome> result;

            crypto = new BouncyCastleScepCrypto();
            KeySpec.Parse("rsa:2048", out spec, out _);
            crypto.GenerateKey(spec, out existing_key, out _);
            expired_cert = new X509Certificate2(server.Ca.IssueExpired(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

            client = MakeClient(server, crypto);
            request = new RenewRequest {
                Subject = "CN=poodle",
                ExistingCertificate = expired_cert,
                ExistingKey = existing_key,
                Variant = RenewalVariant.Expired,
                CaCertificate = server.Ca.CertificateBcl,
            };

            result = client.Renew(request);
            Assert.Equal(ScepClientResult.ServerFailure, result.Status);
            Assert.Equal(FailInfo.BadRequest, result.Value.FailInfo);
        }).GetAwaiter().GetResult();
#pragma warning restore xUnit1031
    }
}
