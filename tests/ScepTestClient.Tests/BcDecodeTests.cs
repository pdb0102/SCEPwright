using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcDecodeTests {
    [Fact]
    public void Decodes_success_certrep_with_issued_cert() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] csr_der;
        Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest parsed_csr;
        Org.BouncyCastle.X509.X509Certificate issued;
        System.Security.Cryptography.X509Certificates.X509Certificate2 client_cert;
        byte[] cert_rep;
        PkiMessage decoded;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        // client builds a CSR; CA issues from its public key
        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=poodle", out _);
        Assert.True(crypto.EncodeCsr(csr, out csr_der, out _));
        parsed_csr = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed_csr.GetPublicKey(), "CN=poodle");

        // the envelope recipient is the client's own self-signed cert wrapping the same key.
        // Since issued was issued FOR the client's public key, using issued as the recipient cert is valid.
        client_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(issued.GetEncoded());

        cert_rep = ca.BuildSuccessCertRep(issued, client_cert, "abc123", new byte[16]);

        Assert.True(crypto.DecodePkiMessage(cert_rep, key, CodecOptions.LenientParsing, out decoded, out error), error);
        Assert.Equal(PkiStatus.Success, decoded.PkiStatus);
        Assert.True(decoded.SignatureValid);
        Assert.Single(decoded.IssuedCerts);
    }
}
