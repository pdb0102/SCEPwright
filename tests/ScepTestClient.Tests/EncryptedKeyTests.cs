using System.IO;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class EncryptedKeyTests {
    [Fact]
    public void Encrypted_pkcs8_round_trips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] enc;
        IScepKey imported;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.True(crypto.ExportPrivateKeyPkcs8Encrypted(key, "s3cret", out enc, out _));
        Assert.True(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "s3cret", out imported, out string err), err);
        Assert.Equal(2048, imported.SizeBits);
        Assert.False(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "wrong", out _, out _));
    }

    [Fact]
    public void Store_writes_encrypted_key_file() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 cert;
        string root;
        CertStore store;
        string cert_id;
        IScepKey loaded_key;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        cert = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=poodle").GetEncoded());

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        cert_id = store.Save("fake", cert, key, crypto, challenge_password: null, renewed_from: null, transaction_id: null, passphrase: "s3cret");

        string cert_dir;
        cert_dir = Path.Combine(root, "servers", "fake", "certificates", cert_id);
        Assert.True(File.Exists(Path.Combine(cert_dir, "key.pkcs8.enc")));
        Assert.False(File.Exists(Path.Combine(cert_dir, "key.pkcs8")));

        Assert.True(store.Load("fake", cert_id, crypto, out _, out loaded_key, out _, out string err, passphrase: "s3cret"), err);
        Assert.Equal(2048, loaded_key.SizeBits);
    }
}
