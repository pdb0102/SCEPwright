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
    public async Task Ndes_ScrapesRealMsNdesPage_NotTheCaThumbprint() {
        FakeHttpEndpoint endpoint;
        NdesChallengeSource source;
        HttpClient http;
        ScepResult<string> result;
        string template;
        string thumbprint;
        string challenge;
        string admin_html;

        // The verbatim NDES mscep_admin page. {0} = CA-cert thumbprint (a 40-hex decoy that appears
        // BEFORE the challenge), {1} = one-time challenge password, {2} = expiry minutes.
        template = """<HTML><Head><Meta HTTP-Equiv="Content-Type" Content="text/html; charset=UTF-8"><Title>Network Device Enrollment Service</Title></Head><Body BgColor=#FFFFFF><Font ID=locPageFont Face="Arial"><Table Border=0 CellSpacing=0 CellPadding=4 Width=100% BgColor=#008080><TR><TD><Font ID=locPageTitleFont Face="Arial" Size=-1 Color=#FFFFFF><LocID ID=locMSCertSrv>Network Device Enrollment Service</LocID></Font></TD></TR></Table><P ID=locPageTitle> Network Device Enrollment Service allows you to obtain certificates for routers or other network devices using the Simple Certificate Enrollment Protocol (SCEP). </P><P> To complete certificate enrollment for your network device you will need the following information: <P> The thumbprint (hash value) for the CA certificate is: <B> {0} </B> <P> The enrollment challenge password is: <B> {1} </B> <P> This password can be used only once and will expire within {2} minutes. <P> Each enrollment requires a new challenge password. You can refresh this web page to obtain a new challenge password. </P> <P ID=locPageDesc> For more information see  <A HREF=http://go.microsoft.com/fwlink/?LinkId=67852>Using Network Device Enrollment Service </A>. </P> <P></Font></Body></HTML>""";
        thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";
        challenge = "A3F9C7E1B8D40526";
        admin_html = template.Replace("{0}", thumbprint).Replace("{1}", challenge).Replace("{2}", "60");

        http = new HttpClient();
        endpoint = await FakeHttpEndpoint.StartAsync(challenge, admin_html);
        try {
            source = new NdesChallengeSource(http, endpoint.BaseUrl + "certsrv/mscep_admin/", "ndesadmin", "pw");
            result = await source.GetAsync();
            Assert.True(result.IsOk, result.Error);
            Assert.Equal(challenge, result.Value);
            Assert.NotEqual(thumbprint, result.Value);
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
