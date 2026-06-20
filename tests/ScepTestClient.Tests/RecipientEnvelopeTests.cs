using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using ScepTestClient.Core;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

// The provider builds the EnvelopedData via BcEnvelope, branching by the recipient cert's algorithm.
// RSA key-transport is exercised end-to-end elsewhere; here we assert the unsupported recipient kinds
// fail cleanly (no throw) with a recognizable message that Core can turn into a finding.
public sealed class RecipientEnvelopeTests {
    // ML-KEM has no CMS recipient generator in BouncyCastle 2.5.0, so it must fail cleanly (no throw)
    // with a recognizable message. (EC and RSA recipients ARE supported — see the round-trip tests.)
    [Fact]
    public void Mlkem_recipient_fails_cleanly() {
        BouncyCastleScepCrypto crypto;
        X509Certificate2 recipient;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;
        bool ok;

        crypto = new BouncyCastleScepCrypto();
        recipient = TestCertFactory.Make("ml-kem", KeyUsage.KeyEncipherment);
        builder = ScepRequestBuilder.For(crypto)
            .CaCertificate(recipient)
            .MessageType(ScepTestClient.CryptoApi.MessageType.PkcsReq)
            .Subject("CN=recip-test")
            .KeySpec("rsa:2048");
        Assert.True(builder.Build(out message, out subject_key, out error), error);

        ok = message.Encode(crypto, out der, out error);

        Assert.False(ok);
        Assert.Contains("ML-KEM", error);
    }

    [Fact]
    public void Rsa_recipient_still_envelopes() {
        BouncyCastleScepCrypto crypto;
        X509Certificate2 recipient;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;

        crypto = new BouncyCastleScepCrypto();
        recipient = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment);
        builder = ScepRequestBuilder.For(crypto)
            .CaCertificate(recipient)
            .MessageType(ScepTestClient.CryptoApi.MessageType.PkcsReq)
            .Subject("CN=recip-test")
            .KeySpec("rsa:2048");
        Assert.True(builder.Build(out message, out subject_key, out error), error);

        Assert.True(message.Encode(crypto, out der, out error), error);
        Assert.True(der.Length > 0);
    }
}
