using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Pkcs;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class ScepClientTests {
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
    public async Task Enroll_returns_issued_certificate() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
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

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=poodle", out _);
        crypto.EncodeCsr(csr, out csr_der, out _);
        parsed_csr = new Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed_csr.GetPublicKey(), "CN=poodle");
        client_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(issued.GetEncoded());
        cert_rep = ca.BuildSuccessCertRep(issued, client_cert, "tx1", new byte[16]);

        handler = new CannedHandler { CaCert = ca.CertificateBcl.RawData, Pki = cert_rep };
        Assert.Equal(ScepClientResult.Ok, ScepClient.Create(
            new ServerConfig { Id = "fake", Url = new Uri("http://host/scep"), PreferPost = true },
            crypto, handler, out client, out _));

        request = new EnrollRequest { Subject = "CN=poodle", Key = key, CaCertificate = ca.CertificateBcl };
        result = await client.EnrollAsync(request);

        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);

        // sync parity
        ScepResult<EnrollOutcome> sync_result;
        sync_result = client.Enroll(request);
        Assert.True(sync_result.IsOk);
        Assert.NotNull(sync_result.Value.Certificate);
    }

    [Fact]
    public void Trace_event_fires() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        CannedHandler handler;
        ScepClient client;
        List<ScepTraceEvent> events;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        handler = new CannedHandler { CaCert = ca.CertificateBcl.RawData };
        ScepClient.Create(new ServerConfig { Id = "fake", Url = new Uri("http://host/scep") }, crypto, handler, out client, out _);
        events = new List<ScepTraceEvent>();
        client.Trace += events.Add;

        client.GetCaCert();
        Assert.NotEmpty(events);
    }
}
