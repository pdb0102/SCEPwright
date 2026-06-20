using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace ScepTestClient.Tests.Fakes;

public sealed class FakeScepServer : IAsyncDisposable {
    private readonly WebApplication _app;
    public Uri ScepUrl { get; private set; }
    public TestCa Ca { get; }
    public string CaCapsBody { get; set; } = "POSTPKIOperation\nSHA-256\nAES\n";

    private FakeScepServer(WebApplication app, TestCa ca) { _app = app; Ca = ca; ScepUrl = new Uri("http://127.0.0.1/scep"); }

    public static async Task<FakeScepServer> StartAsync() => await StartAsync(null);

    public static async Task<FakeScepServer> StartAsync(TestCa? ca_override) {
        WebApplicationBuilder builder;
        WebApplication app;
        TestCa ca;
        FakeScepServer self;

        ca = ca_override ?? TestCa.Create();
        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        self = new FakeScepServer(app, ca);

        app.MapGet("/scep", async (HttpContext ctx) => {
            string op;

            op = ctx.Request.Query["operation"].ToString();
            if (op == "GetCACaps") { await ctx.Response.WriteAsync(self.CaCapsBody); return; }
            if (op == "GetCACert") {
                byte[] bundle;

                bundle = ca.GetCaCertBundleDer();
                ctx.Response.ContentType = ca.EncryptionCert is null ? "application/x-x509-ca-cert" : "application/x-x509-ca-ra-cert";
                await ctx.Response.Body.WriteAsync(bundle);
                return;
            }
            ctx.Response.StatusCode = 400;
        });

        app.MapPost("/scep", async (HttpContext ctx) => {
            MemoryStream ms;
            byte[] request_der;
            byte[] response;
            string message_type;

            ms = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms);
            request_der = ms.ToArray();
            message_type = ca.PeekMessageType(request_der);

            if (message_type == "21") { response = ca.HandleGetCert(request_der); }
            else if (message_type == "22") { response = ca.HandleGetCrl(request_der); }
            else if (message_type == "20") { response = ca.HandlePoll(request_der); }
            else { response = ca.HandlePkiOperation(request_der); }

            ctx.Response.ContentType = "application/x-pki-message";
            await ctx.Response.Body.WriteAsync(response);
        });

        await app.StartAsync();

        string base_url;
        base_url = app.Urls.First();
        self.ScepUrl = new Uri(new Uri(base_url), "/scep");
        return self;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
