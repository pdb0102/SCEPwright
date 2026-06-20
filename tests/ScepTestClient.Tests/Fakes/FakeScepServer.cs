using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace ScepTestClient.Tests.Fakes;

// A fake SCEP server. Besides the default /scep endpoint it also stands up a set of ready-to-use
// per-profile endpoints at /scep/<profile>, each backed by its own TestCa with a specific
// signing/encryption certificate shape — so a real SCEP client (or a scripted test) can exercise
// every recipient combination just by starting the server and hitting the right URL.
public sealed class FakeScepServer : IAsyncDisposable {
    private readonly WebApplication _app;
    private readonly Dictionary<string, TestCa> _profiles;
    private string _base_url = "http://127.0.0.1:0";

    public Uri ScepUrl { get; private set; }
    public TestCa Ca { get; }
    public string CaCapsBody { get; set; } = "POSTPKIOperation\nSHA-256\nAES\n";
    public IReadOnlyDictionary<string, TestCa> Profiles => _profiles;

    private FakeScepServer(WebApplication app, TestCa ca, Dictionary<string, TestCa> profiles) {
        _app = app;
        Ca = ca;
        _profiles = profiles;
        ScepUrl = new Uri("http://127.0.0.1/scep");
    }

    public static async Task<FakeScepServer> StartAsync() => await StartAsync(null);

    public static async Task<FakeScepServer> StartAsync(TestCa? ca_override) {
        WebApplicationBuilder builder;
        WebApplication app;
        TestCa ca;
        Dictionary<string, TestCa> profiles;
        FakeScepServer self;
        string base_url;

        ca = ca_override ?? TestCa.Create();
        profiles = new Dictionary<string, TestCa> {
            { "rsa", TestCa.Create() },
            { "rsa-split", TestCa.CreateWithRaEncryption("rsa") },
            { "ec-encrypt", TestCa.CreateWithRaEncryption("ec") },
            { "ec-dual", TestCa.Create("ec") },
            { "ecdsa-rsa", TestCa.CreateWithRaEncryption("rsa", "ec") },
            { "mldsa-rsa", TestCa.CreateWithRaEncryption("rsa", "ml-dsa") },
            { "mldsa-only", TestCa.Create("ml-dsa") },
            { "mlkem-encrypt", TestCa.CreateWithRaEncryption("ml-kem") },
            { "signing-only", TestCa.CreateSigningOnly() },
        };

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        self = new FakeScepServer(app, ca, profiles);

        // Default endpoint (back-compat): /scep -> the default or caller-supplied CA.
        app.MapGet("/scep", (HttpContext ctx) => HandleGet(self.Ca, self.CaCapsBody, ctx));
        app.MapPost("/scep", (HttpContext ctx) => HandlePost(self.Ca, ctx));

        // One ready-to-go endpoint per profile.
        foreach (KeyValuePair<string, TestCa> profile in profiles) {
            TestCa profile_ca;

            profile_ca = profile.Value;
            app.MapGet($"/scep/{profile.Key}", (HttpContext ctx) => HandleGet(profile_ca, self.CaCapsBody, ctx));
            app.MapPost($"/scep/{profile.Key}", (HttpContext ctx) => HandlePost(profile_ca, ctx));
        }

        await app.StartAsync();

        base_url = app.Urls.First();
        self._base_url = base_url;
        self.ScepUrl = new Uri(new Uri(base_url), "/scep");
        return self;
    }

    public Uri ProfileUrl(string name) => new Uri(new Uri(_base_url), $"/scep/{name}");

    private static async Task HandleGet(TestCa ca, string caps_body, HttpContext ctx) {
        string op;
        byte[] bundle;

        op = ctx.Request.Query["operation"].ToString();
        if (op == "GetCACaps") { await ctx.Response.WriteAsync(caps_body); return; }
        if (op == "GetCACert") {
            bundle = ca.GetCaCertBundleDer();
            ctx.Response.ContentType = ca.EncryptionCert is null ? "application/x-x509-ca-cert" : "application/x-x509-ca-ra-cert";
            await ctx.Response.Body.WriteAsync(bundle);
            return;
        }
        ctx.Response.StatusCode = 400;
    }

    private static async Task HandlePost(TestCa ca, HttpContext ctx) {
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
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
