using System.IO;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class CertStoreLineageTests {
    [Fact]
    public void Save_records_lineage_and_load_round_trips() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 cert;
        CertStore store;
        string root;
        string cert_id;
        X509Certificate2 loaded_cert;
        IScepKey loaded_key;
        CertStore.CertRecord record;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        cert = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=poodle").GetEncoded());

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        cert_id = store.Save("fake", cert, key, crypto, challenge_password: null, renewed_from: "old-id", transaction_id: "tx-1");

        Assert.True(store.Load("fake", cert_id, crypto, out loaded_cert, out loaded_key, out record, out error), error);
        Assert.Equal("old-id", record.RenewedFrom);
        Assert.Equal("tx-1", record.TransactionId);
        Assert.Equal(cert.Thumbprint, loaded_cert.Thumbprint);
        Assert.Equal(2048, loaded_key.SizeBits);
        Assert.Equal("fake", store.FindServerForCert(cert_id));
    }
}
