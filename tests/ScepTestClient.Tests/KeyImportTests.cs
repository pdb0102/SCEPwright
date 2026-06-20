using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class KeyImportTests {
    [Fact]
    public void Export_then_import_round_trips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] der;
        IScepKey imported;
        byte[] der2;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.True(crypto.ExportPrivateKeyPkcs8(key, out der, out _));
        Assert.True(crypto.ImportPrivateKeyPkcs8(der, out imported, out string import_error), import_error);
        Assert.Equal(key.AlgorithmOid, imported.AlgorithmOid);
        Assert.Equal(2048, imported.SizeBits);

        Assert.True(crypto.ExportPrivateKeyPkcs8(imported, out der2, out _));
        Assert.Equal(der, der2);
    }
}
