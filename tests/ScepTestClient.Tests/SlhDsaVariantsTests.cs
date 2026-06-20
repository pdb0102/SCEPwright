using Org.BouncyCastle.Pkcs;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

// SLH-DSA (FIPS 205) SHA2 family: all six small (s) and fast (f) parameter sets.
// NIST CSOR sigAlgs arc 2.16.840.1.101.3.4.3.{20..25} is sequential across the SHA2 sets.
public sealed class SlhDsaVariantsTests {
    [Theory]
    [InlineData("slh-dsa:128s", "2.16.840.1.101.3.4.3.20")]
    [InlineData("slh-dsa:128f", "2.16.840.1.101.3.4.3.21")]
    [InlineData("slh-dsa:192s", "2.16.840.1.101.3.4.3.22")]
    [InlineData("slh-dsa:192f", "2.16.840.1.101.3.4.3.23")]
    [InlineData("slh-dsa:256s", "2.16.840.1.101.3.4.3.24")]
    [InlineData("slh-dsa:256f", "2.16.840.1.101.3.4.3.25")]
    public void Generates_all_sha2_sets_with_correct_oid(string key_spec, string expected_oid) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse(key_spec, out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.Equal(expected_oid, key.AlgorithmOid);
    }

    [Fact]
    public void Fast_variant_pkcs8_roundtrips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        IScepKey imported;
        byte[] der;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("slh-dsa:128f", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.True(crypto.ExportPrivateKeyPkcs8(key, out der, out error), error);
        Assert.True(crypto.ImportPrivateKeyPkcs8(der, out imported, out error), error);
        Assert.Equal(key.AlgorithmOid, imported.AlgorithmOid);
    }

    [Fact]
    public void Fast_variant_csr_parses_and_verifies() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("slh-dsa:128f", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=slh-test", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);
        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
    }
}
