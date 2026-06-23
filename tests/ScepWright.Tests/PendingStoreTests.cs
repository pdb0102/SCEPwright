using System.IO;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using Xunit;

namespace ScepWright.Tests;

// A PENDING enrollment must persist the subject key + request so a later `poll` can pair the issued
// cert with its key. Without this, the polled cert has no key on disk and never appears in `certs list`.
public class PendingStoreTests {
    [Fact]
    public void Save_then_load_round_trips_the_key_and_metadata() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        IScepKey loaded;
        PendingStore.PendingRecord rec;
        string root;
        string error;
        PendingStore store;
        byte[] original_der;
        byte[] loaded_der;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new PendingStore(root);

        store.Save("fake", "txnabc", key, crypto, key_spec_text: "rsa:2048");

        Assert.True(store.TryLoad("fake", "txnabc", crypto, out loaded, out rec, out error), error);
        Assert.Equal("rsa:2048", rec.KeySpec);
        crypto.ExportPrivateKeyPkcs8(key, out original_der, out _);
        crypto.ExportPrivateKeyPkcs8(loaded, out loaded_der, out _);
        Assert.Equal(original_der, loaded_der);
    }

    [Fact]
    public void Delete_removes_the_pending_record() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string root;
        string error;
        PendingStore store;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new PendingStore(root);

        store.Save("fake", "txnabc", key, crypto, key_spec_text: "rsa:2048");
        store.Delete("fake", "txnabc");

        Assert.False(store.TryLoad("fake", "txnabc", crypto, out _, out _, out error));
        Assert.Contains("txnabc", error);
    }

    [Fact]
    public void TryLoad_missing_returns_false_naming_the_transaction() {
        BouncyCastleScepCrypto crypto;
        string root;
        string error;
        PendingStore store;

        crypto = new BouncyCastleScepCrypto();
        root = Directory.CreateTempSubdirectory().FullName;
        store = new PendingStore(root);

        Assert.False(store.TryLoad("fake", "nope", crypto, out _, out _, out error));
        Assert.Contains("nope", error);
    }
}
