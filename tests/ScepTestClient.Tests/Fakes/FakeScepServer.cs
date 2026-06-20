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
    public Uri ScepUrl { get; }
    public TestCa Ca { get; }

    private FakeScepServer(WebApplication app, Uri url, TestCa ca) { _app = app; ScepUrl = url; Ca = ca; }

    public static async Task<FakeScepServer> StartAsync() {
        WebApplicationBuilder builder;
        WebApplication app;
        TestCa ca;

        ca = TestCa.Create();
        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();

        app.MapGet("/scep", async (HttpContext ctx) => {
            string op;

            op = ctx.Request.Query["operation"].ToString();
            if (op == "GetCACaps") { await ctx.Response.WriteAsync("POSTPKIOperation\nSHA-256\nAES\n"); return; }
            if (op == "GetCACert") {
                ctx.Response.ContentType = "application/x-x509-ca-cert";
                await ctx.Response.Body.WriteAsync(ca.Certificate.GetEncoded());
                return;
            }
            ctx.Response.StatusCode = 400;
        });

        app.MapPost("/scep", async (HttpContext ctx) => {
            MemoryStream ms;
            byte[] request_der;
            byte[] cert_rep;

            ms = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms);
            request_der = ms.ToArray();
            cert_rep = ca.HandlePkiOperation(request_der);
            ctx.Response.ContentType = "application/x-pki-message";
            await ctx.Response.Body.WriteAsync(cert_rep);
        });

        await app.StartAsync();

        string base_url;
        Uri scep;
        base_url = app.Urls.First();
        scep = new Uri(new Uri(base_url), "/scep");
        return new FakeScepServer(app, scep, ca);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
