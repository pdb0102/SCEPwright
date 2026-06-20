using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace ScepTestClient.Tests.Fakes;

public sealed class FakeHttpEndpoint : System.IAsyncDisposable {
    private readonly WebApplication _app;

    public System.Uri BaseUrl { get; }

    private FakeHttpEndpoint(WebApplication app, System.Uri base_url) {
        _app = app;
        BaseUrl = base_url;
    }

    public static async Task<FakeHttpEndpoint> StartAsync(string challenge, string? admin_html = null) {
        WebApplicationBuilder builder;
        WebApplication app;
        System.Uri url;

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();

        app.MapPost("/challenge", async (HttpContext ctx) => {
            await ctx.Response.WriteAsync($"{{ \"challengePassword\": \"{challenge}\" }}");
        });
        app.MapGet("/certsrv/mscep_admin/", async (HttpContext ctx) => {
            if (!ctx.Request.Headers.ContainsKey("Authorization")) {
                ctx.Response.StatusCode = 401;
                return;
            }
            await ctx.Response.WriteAsync(admin_html ?? $"<html><body>enrollment challenge password is <b>{challenge}</b></body></html>");
        });

        await app.StartAsync();
        url = new System.Uri(app.Urls.First());
        return new FakeHttpEndpoint(app, url);
    }

    public async ValueTask DisposeAsync() { await _app.DisposeAsync(); }
}
