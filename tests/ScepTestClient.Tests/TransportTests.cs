using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ScepTestClient.Core.Transport;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class TransportTests {
    private sealed class StubHandler : HttpMessageHandler {
        public Uri? LastUri;
        public byte[] Response = { 1, 2, 3 };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
            LastUri = request.RequestUri;
            return Task.FromResult(BuildResponse());
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) {
            LastUri = request.RequestUri;
            return BuildResponse();
        }

        private HttpResponseMessage BuildResponse() {
            HttpResponseMessage resp;

            resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Response) };
            return resp;
        }
    }

    [Fact]
    public async Task Get_builds_operation_query_and_returns_bytes() {
        StubHandler stub;
        ScepHttpTransport transport;
        ScepResult<byte[]> sync;
        ScepResult<byte[]> async;

        stub = new StubHandler();
        transport = new ScepHttpTransport(new HttpClient(stub), new Uri("http://host/scep"), TimeSpan.FromSeconds(30));

        async = await transport.GetAsync("GetCACaps", "abc");
        Assert.True(async.IsOk);
        Assert.Contains("operation=GetCACaps", stub.LastUri!.Query);
        Assert.Contains("message=", stub.LastUri!.Query);

        sync = transport.Get("GetCACaps", "abc");
        Assert.Equal(async.Value, sync.Value);
    }

    [Fact]
    public async Task Post_sends_body_and_returns_bytes() {
        StubHandler stub;
        ScepHttpTransport transport;
        ScepResult<byte[]> result;

        stub = new StubHandler();
        transport = new ScepHttpTransport(new HttpClient(stub), new Uri("http://host/scep"), TimeSpan.FromSeconds(30));

        result = await transport.PostAsync("PKIOperation", new byte[] { 5, 6 });
        Assert.True(result.IsOk);
        Assert.Equal(new byte[] { 1, 2, 3 }, result.Value);
    }
}
