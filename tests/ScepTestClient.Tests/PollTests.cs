using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class PollTests {
    [Fact]
    public async Task Poll_returns_a_cert_for_the_subject() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        result = await client.PollAsync(server.Ca.Certificate.SubjectDN.ToString(), "CN=poodle", "txn-123");
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
        Assert.Equal("txn-123", result.Value.TransactionId);
    }
}
