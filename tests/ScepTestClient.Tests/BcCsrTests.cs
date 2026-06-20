using Org.BouncyCastle.Pkcs;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class BcCsrTests {
    [Fact]
    public void Builds_signed_csr_with_subject_and_challenge() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "s3cret", Sid = "S-1-5-21-1-2-3-1000" };
        Assert.True(csr.SetSubject("CN=poodle", out _));

        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        Assert.Contains("poodle", parsed.GetCertificationRequestInfo().Subject.ToString());
    }
}
