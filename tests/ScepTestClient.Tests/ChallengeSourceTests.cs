using System.Net.Http;
using ScepTestClient.Core.Challenge;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;

namespace ScepTestClient.Tests;

public sealed class ChallengeSourceTests {
    [Fact]
    public void Explicit_ReturnsValue() {
        IChallengeSource source;
        string challenge;
        string error;

        source = new ExplicitChallengeSource("s3cret");
        Assert.True(source.TryGet(out challenge, out error));
        Assert.Equal("s3cret", challenge);
    }

    [Theory]
    [InlineData("http://ndes.example/certsrv/mscep/pkiclient.exe", "http://ndes.example/certsrv/mscep_admin/")]
    [InlineData("https://host/certsrv/mscep", "https://host/certsrv/mscep_admin/")]
    public void AdminUrl_Derives(string scep, string expected) {
        Assert.Equal(expected, NdesAdminUrl.Derive(scep));
    }

    [Fact]
    public async Task Simulator_ReadsChallengePassword() {
        FakeHttpEndpoint endpoint;
        SimulatorChallengeSource source;
        HttpClient http;
        ScepResult<string> result;

        http = new HttpClient();
        endpoint = await FakeHttpEndpoint.StartAsync("sim-challenge-01");
        try {
            source = new SimulatorChallengeSource(http, endpoint.BaseUrl.ToString());
            result = await source.GetAsync();
            Assert.True(result.IsOk, result.Error);
            Assert.Equal("sim-challenge-01", result.Value);
        } finally {
            await endpoint.DisposeAsync();
        }
    }

    [Fact]
    public async Task Ndes_ScrapesChallengeWithBasicAuth() {
        FakeHttpEndpoint endpoint;
        NdesChallengeSource source;
        HttpClient http;
        ScepResult<string> result;

        http = new HttpClient();
        endpoint = await FakeHttpEndpoint.StartAsync("DEADBEEFCAFE1234");
        try {
            source = new NdesChallengeSource(http, endpoint.BaseUrl + "certsrv/mscep_admin/", "ndesadmin", "pw");
            result = await source.GetAsync();
            Assert.True(result.IsOk, result.Error);
            Assert.Equal("DEADBEEFCAFE1234", result.Value);
        } finally {
            await endpoint.DisposeAsync();
        }
    }

    [Fact]
    public async Task Ndes_AnchorsToLabel_IgnoringDecoyHex() {
        FakeHttpEndpoint endpoint;
        NdesChallengeSource source;
        HttpClient http;
        ScepResult<string> result;
        string admin_html;

        admin_html = "<p>thumbprint AABBCCDDEEFF0011</p><p>The enrollment challenge password is: <B>DEADBEEFCAFE1234</B></p>";

        http = new HttpClient();
        endpoint = await FakeHttpEndpoint.StartAsync("DEADBEEFCAFE1234", admin_html);
        try {
            source = new NdesChallengeSource(http, endpoint.BaseUrl + "certsrv/mscep_admin/", "ndesadmin", "pw");
            result = await source.GetAsync();
            Assert.True(result.IsOk, result.Error);
            Assert.Equal("DEADBEEFCAFE1234", result.Value);
        } finally {
            await endpoint.DisposeAsync();
        }
    }
}
