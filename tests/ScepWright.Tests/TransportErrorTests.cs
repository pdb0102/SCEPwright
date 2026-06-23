using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ScepWright.Core.Transport;
using ScepWright.Crypto;
using Xunit;

namespace ScepWright.Tests;

// A 404 alone tells a non-expert nothing; it almost always means the SCEP URL path is wrong.
// A 500 alone is worse: the real reason lives in the response body the server returned, so we
// must surface that body instead of discarding it.
public sealed class TransportErrorTests {
    private sealed class StatusBodyHandler : HttpMessageHandler {
        public HttpStatusCode Status = HttpStatusCode.InternalServerError;
        public string Body = string.Empty;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
            return Task.FromResult(Build());
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) {
            return Build();
        }

        private HttpResponseMessage Build() {
            return new HttpResponseMessage(Status) { Content = new StringContent(Body) };
        }
    }

    [Fact]
    public void Http_404_message_hints_at_the_url_path() {
        string msg;

        msg = ScepHttpTransport.DescribeHttpError(404);
        Assert.Contains("404", msg);
        Assert.Contains("path", msg);
    }

    [Fact]
    public void Other_http_errors_stay_terse() {
        Assert.Equal("HTTP 500", ScepHttpTransport.DescribeHttpError(500));
    }

    [Fact]
    public void Http_error_includes_the_server_response_body() {
        string msg;

        msg = ScepHttpTransport.DescribeHttpError(500, "VedSCEP handler threw NullReferenceException");
        Assert.Contains("500", msg);
        Assert.Contains("VedSCEP handler threw NullReferenceException", msg);
    }

    [Fact]
    public void Empty_error_body_stays_terse() {
        Assert.Equal("HTTP 500", ScepHttpTransport.DescribeHttpError(500, string.Empty));
        Assert.Equal("HTTP 500", ScepHttpTransport.DescribeHttpError(500, "   \r\n  "));
    }

    [Fact]
    public void Long_error_body_is_truncated() {
        string body;
        string msg;

        body = new string('x', 500) + "TAIL";
        msg = ScepHttpTransport.DescribeHttpError(500, body);

        Assert.True(msg.Length < 300, $"expected a truncated message, got {msg.Length} chars");
        Assert.DoesNotContain("TAIL", msg);
        Assert.Contains("…", msg);
    }

    [Fact]
    public async Task Get_surfaces_the_server_error_body_on_non_2xx() {
        StatusBodyHandler stub;
        ScepHttpTransport transport;
        ScepResult<byte[]> async_result;
        ScepResult<byte[]> sync_result;

        stub = new StatusBodyHandler { Status = HttpStatusCode.InternalServerError, Body = "vedscep exploded: see Windows event log" };
        transport = new ScepHttpTransport(new HttpClient(stub), new Uri("https://host/vedscep/"), TimeSpan.FromSeconds(30));

        async_result = await transport.GetAsync("GetCACaps", string.Empty);
        Assert.False(async_result.IsOk);
        Assert.Equal(ScepClientResult.NetworkError, async_result.Status);
        Assert.Contains("500", async_result.Error);
        Assert.Contains("vedscep exploded", async_result.Error);

        sync_result = transport.Get("GetCACaps", string.Empty);
        Assert.False(sync_result.IsOk);
        Assert.Contains("vedscep exploded", sync_result.Error);
    }

    [Fact]
    public void DescribeGet_returns_the_resolved_request_url() {
        ScepHttpTransport transport;
        string url;

        transport = new ScepHttpTransport(new HttpClient(), new Uri("https://host/vedscep/"), TimeSpan.FromSeconds(30));
        url = transport.DescribeGet("GetCACaps", string.Empty);

        Assert.Contains("https://host/vedscep/", url);
        Assert.Contains("operation=GetCACaps", url);
    }
}
