using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class BcKeyTests {
    [Fact]
    public void Generates_rsa_2048() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("rsa:2048", out spec, out _));
        Assert.True(crypto.GenerateKey(spec, out key, out error));
        Assert.Equal("1.2.840.113549.1.1.1", key.AlgorithmOid);
        Assert.Equal(2048, key.SizeBits);
    }

    [Fact]
    public void Advertises_classical_algorithms() {
        BouncyCastleScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.Contains("2.16.840.1.101.3.4.2.1", crypto.Capabilities.Digests);
        Assert.Contains("2.16.840.1.101.3.4.1.2", crypto.Capabilities.ContentEncryption);
    }
}
