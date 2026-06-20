using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class DomainObjectTests {
    private sealed class FakeCrypto : IScepCrypto {
        public int EncodeCalls;
        public int DecodeCalls;
        public CryptoCapabilities Capabilities => new();

        public bool GenerateKey(KeySpec spec, out IScepKey key, out string error) { key = null!; error = "not used"; return false; }

        public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error) { der = new byte[] { 1 }; error = string.Empty; return true; }

        public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error) { EncodeCalls++; der = new byte[] { 9, 9 }; error = string.Empty; return true; }

        public bool DecodePkiMessage(byte[] der, IScepKey recipientKey, CodecOptions options, out PkiMessage message, out string error) { DecodeCalls++; message = new PkiMessage { MessageType = MessageType.CertRep }; error = string.Empty; return true; }

        public bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error) { certs = System.Array.Empty<X509Certificate2>(); error = string.Empty; return true; }

        public bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error) { der = System.Array.Empty<byte>(); error = string.Empty; return true; }

        public bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error) { key = null!; error = string.Empty; return true; }

        public bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error) { der = System.Array.Empty<byte>(); error = string.Empty; return false; }

        public bool ImportPrivateKeyPkcs8Encrypted(byte[] der, string passphrase, out IScepKey key, out string error) { key = null!; error = string.Empty; return false; }
    }

    [Fact]
    public void Subject_must_be_non_empty() {
        Pkcs10 csr;
        string error;

        csr = new Pkcs10();
        Assert.False(csr.SetSubject("", out error));
        Assert.True(csr.SetSubject("CN=poodle", out error));
        Assert.Equal("CN=poodle", csr.Subject);
    }

    [Fact]
    public void Encode_delegates_to_provider() {
        FakeCrypto crypto;
        PkiMessage pki;
        byte[] der;
        string error;

        crypto = new FakeCrypto();
        pki = new PkiMessage { MessageType = MessageType.PkcsReq };

        Assert.True(pki.Encode(crypto, out der, out error));
        Assert.Equal(1, crypto.EncodeCalls);
        Assert.Equal(new byte[] { 9, 9 }, der);
    }

    [Fact]
    public void Decode_delegates_to_provider() {
        FakeCrypto crypto;
        PkiMessage parsed;
        string error;

        crypto = new FakeCrypto();

        Assert.True(PkiMessage.Decode(crypto, new byte[] { 0 }, key: null!, CodecOptions.LenientParsing, out parsed, out error));
        Assert.Equal(1, crypto.DecodeCalls);
        Assert.Equal(MessageType.CertRep, parsed.MessageType);
    }
}
