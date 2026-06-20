using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

// End-to-end: the client must parse the GetCACert bundle, select the encryption cert by KeyUsage,
// and envelope the request to it (not blindly to the first / CA signing cert).
public sealed class SplitCertEnrollTests {
    [Fact]
    public async Task Enroll_through_separate_ra_encryption_cert_succeeds() {
        FakeScepServer server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync(TestCa.CreateWithRaEncryption());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "split", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=split-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // Succeeds only if the client enveloped to the RA encryption cert: the CA/signing cert
            // lacks keyEncipherment, and the server decrypts with the separate RA key.
            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Enroll_against_signing_only_ca_fails_with_conformance_finding() {
        FakeScepServer server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync(TestCa.CreateSigningOnly());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "signonly", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=signonly-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // The server's only cert lacks keyEncipherment, so the request cannot be enveloped.
            Assert.False(outcome.IsOk);
            Assert.Contains("envelop", outcome.Error);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Enroll_through_ec_key_agreement_ra_cert_succeeds() {
        FakeScepServer server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync(TestCa.CreateWithRaEncryption("ec"));
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "ec", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=ec-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // Succeeds only if the client enveloped to the EC RA cert via ECDH key agreement and the
            // server decrypted with the EC private key.
            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }
}
