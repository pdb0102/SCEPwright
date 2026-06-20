using System;
using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

// Drives the ready-to-go per-profile endpoints. A single server start exposes every recipient
// combination; each test just points a client at the matching /scep/<profile> URL.
public sealed class EndpointMatrixTests {
    [Theory]
    [InlineData("rsa")]
    [InlineData("rsa-split")]
    [InlineData("ec-encrypt")]
    public async Task Enroll_succeeds_against_supported_profile(string profile) {
        FakeScepServer server;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync();
        try {
            outcome = Enroll(server.ProfileUrl(profile), profile);
            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Theory]
    [InlineData("mlkem-encrypt", "ML-KEM")]
    [InlineData("signing-only", "envelop")]
    public async Task Enroll_fails_with_finding_against_unsupported_profile(string profile, string expected_in_error) {
        FakeScepServer server;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync();
        try {
            outcome = Enroll(server.ProfileUrl(profile), profile);
            Assert.False(outcome.IsOk);
            Assert.Contains(expected_in_error, outcome.Error);
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepResult<EnrollOutcome> Enroll(Uri url, string id) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = id, Url = url, PreferPost = true }, crypto, handler: null, out client, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        request = new EnrollRequest { Subject = $"CN={id}", Key = key };
        return client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));
    }
}
