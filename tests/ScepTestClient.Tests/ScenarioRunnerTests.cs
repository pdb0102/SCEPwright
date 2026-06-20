using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Testing;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class ScenarioRunnerTests {
    [Fact]
    public void Parse_ReadsSteps() {
        string json;
        ScenarioFile scenario;
        string error;

        json = "{ \"name\": \"sweep\", \"steps\": [ { \"name\": \"caps\", \"run\": \"getcacaps\", \"expect\": \"pass\" }, { \"name\": \"md5\", \"run\": \"enroll\", \"args\": { \"digest\": \"MD5\" }, \"expect\": \"badAlg\" } ] }";
        Assert.True(ScenarioRunner.Parse(json, out scenario, out error), error);
        Assert.Equal(2, scenario.Steps.Count);
        Assert.Equal("badAlg", scenario.Steps[1].Expect);
    }

    [Fact]
    public async Task Run_AggregatesIntoOneReport() {
        FakeScepServer server;
        ScepClient client;
        ScenarioFile scenario;
        TestReport report;
        string error;

        server = await FakeScepServer.StartAsync();
        try {
            client = BuildClientFor(server, out _);
            ScenarioRunner.Parse("{ \"name\": \"s\", \"steps\": [ { \"name\": \"caps\", \"run\": \"getcacaps\", \"expect\": \"pass\" }, { \"name\": \"md5\", \"run\": \"enroll\", \"args\": { \"digest\": \"MD5\" }, \"expect\": \"badAlg\" } ] }", out scenario, out error);
            report = ScenarioRunner.Run(client, scenario, server.Ca.CertificateBcl);
            Assert.Equal("scenario", report.Mode);
            Assert.Equal(2, report.Results.Count);
            Assert.All(report.Results, r => Assert.Equal(CheckOutcome.Passed, r.Outcome));
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepClient BuildClientFor(FakeScepServer server, out IScepCrypto crypto) {
        BouncyCastleScepCrypto bc_crypto;
        ScepClient client;

        bc_crypto = new BouncyCastleScepCrypto();
        crypto = bc_crypto;
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, bc_crypto, handler: null, out client, out _);
        return client;
    }
}
