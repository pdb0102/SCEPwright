using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Pkcs;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class OrchestrationTests {
    private sealed class CannedHandler : HttpMessageHandler {
        public byte[] CaCert = Array.Empty<byte>();
        public byte[] Pki = Array.Empty<byte>();

        private HttpResponseMessage Respond(HttpRequestMessage req) {
            string query;
            byte[] body;

            query = req.RequestUri!.Query;
            body = query.Contains("operation=GetCACert") ? CaCert : Pki;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(Respond(request));
        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct)
            => Respond(request);
    }

    [Fact]
    public async Task GetNewCertificateAsync_fetches_ca_cert_enrolls_stores_and_logs() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] csr_der;
        Pkcs10CertificationRequest parsed_csr;
        Org.BouncyCastle.X509.X509Certificate issued;
        System.Security.Cryptography.X509Certificates.X509Certificate2 client_cert;
        byte[] cert_rep;
        CannedHandler handler;
        ScepClient client;
        EnrollRequest request;
        ScepResult<EnrollOutcome> result;
        string root;
        string cert_dir;
        string history_file;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=poodle", out _);
        crypto.EncodeCsr(csr, out csr_der, out _);
        parsed_csr = new Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed_csr.GetPublicKey(), "CN=poodle");
        client_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(issued.GetEncoded());
        cert_rep = ca.BuildSuccessCertRep(issued, client_cert, "tx", new byte[16]);

        handler = new CannedHandler { CaCert = ca.CertificateBcl.RawData, Pki = cert_rep };
        Assert.Equal(ScepClientResult.Ok, ScepClient.Create(
            new ServerConfig { Id = "fake", Url = new Uri("http://host/scep"), PreferPost = true },
            crypto, handler, out client, out _));

        root = Directory.CreateTempSubdirectory().FullName;
        request = new EnrollRequest { Subject = "CN=poodle", Key = key };

        result = await client.GetNewCertificateAsync(request, new CertStore(root), new UseRecordLog(root));

        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);

        cert_dir = Path.Combine(root, "servers", "fake", "certificates");
        Assert.True(Directory.Exists(cert_dir), $"Expected certificates directory at {cert_dir}");
        Assert.True(Directory.GetDirectories(cert_dir).Length >= 1, "Expected at least one certificate subdirectory");

        history_file = Path.Combine(root, "servers", "fake", "history.jsonl");
        Assert.True(File.Exists(history_file), $"Expected history file at {history_file}");
        Assert.True(File.ReadAllLines(history_file).Length >= 1, "Expected at least one history record");
    }

    // `diagnose -v` is useless if the operator can't see what was actually requested. GetCaCaps must
    // emit a Debug trace carrying the fully-resolved request URL.
    [Fact]
    public void GetCaCaps_emits_a_debug_trace_with_the_resolved_request_url() {
        BouncyCastleScepCrypto crypto;
        CannedHandler handler;
        ScepClient client;
        System.Collections.Generic.List<ScepTraceEvent> events;

        crypto = new BouncyCastleScepCrypto();
        handler = new CannedHandler { Pki = System.Text.Encoding.ASCII.GetBytes("POSTPKIOperation\nSHA-256") };
        Assert.Equal(ScepClientResult.Ok, ScepClient.Create(
            new ServerConfig { Id = "fake", Url = new Uri("https://host/vedscep/") },
            crypto, handler, out client, out _));

        events = new System.Collections.Generic.List<ScepTraceEvent>();
        client.Trace += events.Add;
        client.GetCaCaps();

        Assert.Contains(events, e => e.Level == TraceLevel.Debug
            && e.Message.Contains("operation=GetCACaps")
            && e.Message.Contains("https://host/vedscep/"));
    }
}
