using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class RenewLifecycleTests {
    [Fact]
    public async Task Enroll_then_renew_chains_lineage() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        ScepResult<EnrollOutcome> enroll;
        string original_id;
        ScepResult<EnrollOutcome> renew;
        string new_id;
        string meta_json;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw", CaCertificate = server.Ca.CertificateBcl },
            store, log);
        Assert.True(enroll.IsOk, enroll.Error);
        original_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();

        renew = await client.RenewCertificateAsync(original_id, store, log);
        Assert.True(renew.IsOk, renew.Error);

        new_id = renew.Value.Certificate!.Thumbprint.ToLowerInvariant();
        meta_json = File.ReadAllText(Path.Combine(root, "servers", "fake", "certificates", new_id, "metadata.json"));
        using JsonDocument doc = JsonDocument.Parse(meta_json);
        Assert.Equal(original_id, doc.RootElement.GetProperty("RenewedFrom").GetString());
    }
}
