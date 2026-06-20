using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class AltKeyCsrTests {
    [Fact]
    public void Alt_key_emits_subject_alt_public_key_info() {
        BouncyCastleScepCrypto crypto;
        KeySpec rsa_spec;
        KeySpec alt_spec;
        IScepKey rsa_key;
        IScepKey alt_key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.Asn1.X509.X509Extensions? exts;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("rsa:2048", out rsa_spec, out error), error);
        Assert.True(KeySpec.Parse("ml-dsa:65", out alt_spec, out error), error);
        Assert.True(crypto.GenerateKey(rsa_spec, out rsa_key, out error), error);
        Assert.True(crypto.GenerateKey(alt_spec, out alt_key, out error), error);

        csr = new Pkcs10 { Key = rsa_key, AltKey = alt_key };
        csr.SetSubject("CN=catalyst", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        exts = ExtensionsFrom(parsed);
        Assert.NotNull(exts!.GetExtension(new DerObjectIdentifier("2.5.29.72")));
    }

    [Fact]
    public void No_alt_key_no_extension() {
        BouncyCastleScepCrypto crypto;
        KeySpec rsa_spec;
        IScepKey rsa_key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.Asn1.X509.X509Extensions? exts;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("rsa:2048", out rsa_spec, out error), error);
        Assert.True(crypto.GenerateKey(rsa_spec, out rsa_key, out error), error);

        csr = new Pkcs10 { Key = rsa_key };
        csr.SetSubject("CN=no-alt", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        exts = ExtensionsFromOrNull(parsed);
        if (exts is not null) {
            Assert.Null(exts.GetExtension(new DerObjectIdentifier("2.5.29.72")));
        }
    }

    private static Org.BouncyCastle.Asn1.X509.X509Extensions ExtensionsFrom(Pkcs10CertificationRequest req) {
        Org.BouncyCastle.Asn1.X509.X509Extensions? exts;

        exts = ExtensionsFromOrNull(req);
        Assert.NotNull(exts);
        return exts!;
    }

    private static Org.BouncyCastle.Asn1.X509.X509Extensions? ExtensionsFromOrNull(Pkcs10CertificationRequest req) {
        Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo info;
        Org.BouncyCastle.Asn1.Asn1Set? attrs;

        info = req.GetCertificationRequestInfo();
        attrs = info.Attributes;
        if (attrs is null) { return null; }
        foreach (Org.BouncyCastle.Asn1.Asn1Encodable enc in attrs) {
            Org.BouncyCastle.Asn1.Pkcs.AttributePkcs attr;

            attr = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs.GetInstance(enc);
            if (attr.AttrType.Id == "1.2.840.113549.1.9.14") {
                return Org.BouncyCastle.Asn1.X509.X509Extensions.GetInstance(attr.AttrValues[0]);
            }
        }
        return null;
    }
}
