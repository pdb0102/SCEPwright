using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class ScepRequestBuilderTests {
    [Fact]
    public void Builds_pkcsreq_self_signed() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;
        bool ok;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        ok = ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .Subject("CN=h")
            .KeySpec("rsa:2048")
            .Digest("SHA-256")
            .Cipher("AES-128")
            .Challenge("pw")
            .Build(out msg, out key, out error);

        Assert.True(ok, error);
        Assert.Equal(MessageType.PkcsReq, msg.MessageType);
        Assert.Equal("CN=h", msg.InnerCsr!.Subject);
        Assert.Equal(Algorithms.OidFor("SHA-256"), msg.DigestAlgorithmOid);
        Assert.Equal(Algorithms.OidFor("AES-128-CBC"), msg.ContentEncryptionAlgorithmOid);
        Assert.Equal("pw", msg.InnerCsr.ChallengePassword);
        Assert.NotNull(key);
        Assert.Same(key, msg.SignerKey);
    }

    [Fact]
    public void Builds_renewalreq_with_existing_signer() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey existing_key;
        X509Certificate2 existing_cert;
        PkiMessage msg;
        IScepKey new_key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out existing_key, out _);
        existing_cert = new X509Certificate2(ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=h").GetEncoded());

        Assert.True(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .MessageType(MessageType.RenewalReq)
            .Subject("CN=h")
            .KeySpec("rsa:2048")
            .SignerCertificate(existing_cert)
            .SignerKey(existing_key)
            .Build(out msg, out new_key, out error), error);

        Assert.Equal(MessageType.RenewalReq, msg.MessageType);
        Assert.Same(existing_cert, msg.SignerCert);
        Assert.Same(existing_key, msg.SignerKey);
        Assert.NotSame(existing_key, new_key);
    }

    [Fact]
    public void Builds_getcert_with_issuer_and_serial() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        Assert.True(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .MessageType(MessageType.GetCert)
            .KeySpec("rsa:2048")
            .IssuerAndSerial("CN=CA", "0A")
            .Build(out msg, out key, out error), error);

        Assert.Equal("CN=CA", msg.IssuerName);
        Assert.Equal("0A", msg.SerialNumber);
        Assert.Null(msg.InnerCsr);
        Assert.NotNull(msg.SignerKey);
    }

    [Fact]
    public void Pkcsreq_without_subject_fails() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        Assert.False(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .KeySpec("rsa:2048")
            .Build(out msg, out key, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
