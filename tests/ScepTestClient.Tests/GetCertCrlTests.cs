using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class GetCertCrlTests {
    [Fact]
    public async Task GetCert_returns_previously_issued_cert() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        string root;
        ScepResult<EnrollOutcome> enroll;
        string serial_hex;
        string issuer_dn;
        ScepResult<System.Security.Cryptography.X509Certificates.X509Certificate2> got;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        root = Directory.CreateTempSubdirectory().FullName;
        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw", CaCertificate = server.Ca.CertificateBcl },
            new CertStore(root), new UseRecordLog(root));
        Assert.True(enroll.IsOk, enroll.Error);

        serial_hex = enroll.Value.Certificate!.SerialNumber;
        issuer_dn = server.Ca.Certificate.SubjectDN.ToString();

        got = await client.GetCertAsync(issuer_dn, serial_hex);
        Assert.True(got.IsOk, got.Error);
        Assert.Equal(serial_hex, got.Value.SerialNumber);
    }

    [Fact]
    public async Task GetCrl_returns_a_crl() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        ScepResult<byte[]> crl;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        crl = await client.GetCrlAsync(server.Ca.Certificate.SubjectDN.ToString(), "01");
        Assert.True(crl.IsOk, crl.Error);
        Assert.NotEmpty(crl.Value);
        Assert.NotNull(new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(crl.Value));
    }
}
