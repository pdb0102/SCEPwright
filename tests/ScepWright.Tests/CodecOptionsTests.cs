using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// Proves CodecOptions are genuinely honored: Strict (0) enforces signature + legacy-digest checks, the
// two explicit flags selectively relax them, and LenientParsing keeps the historical tolerant behavior.
public class CodecOptionsTests {
    private const string OidMessageType = "2.16.840.1.113733.1.9.2";
    private const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
    private const string OidFailInfo = "2.16.840.1.113733.1.9.4";
    private const string OidTransId = "2.16.840.1.113733.1.9.7";
    private const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

    // A real, valid CertRep still decodes under Strict (no regression for well-formed responses).
    [Fact]
    public void Valid_certrep_decodes_under_strict() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
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
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=poodle", out _);
        crypto.EncodeCsr(csr, out csr_der, out _);
        parsed_csr = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed_csr.GetPublicKey(), "CN=poodle");
        client_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(issued.GetEncoded());
        cert_rep = ca.BuildSuccessCertRep(issued, client_cert, "abc123", new byte[16]);

        Assert.True(crypto.DecodePkiMessage(cert_rep, key, CodecOptions.Strict, null, out decoded, out error), error);
        Assert.Equal(PkiStatus.Success, decoded.PkiStatus);
    }

    // A bad-signature response: FAILS under Strict, SUCCEEDS with SkipSignatureVerification or LenientParsing.
    [Fact]
    public void Bad_signature_fails_strict_but_passes_when_relaxed() {
        BouncyCastleScepCrypto crypto;
        IScepKey key;
        byte[] bad_sig;
        PkiMessage decoded;
        string strict_error;
        string skip_error;
        string lenient_error;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out KeySpec spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        bad_sig = BuildFailureCertRep("SHA256WITHRSA", use_wrong_signing_key: true);

        Assert.False(crypto.DecodePkiMessage(bad_sig, key, CodecOptions.Strict, null, out decoded, out strict_error));
        Assert.Contains("signature", strict_error.ToLowerInvariant());

        Assert.True(crypto.DecodePkiMessage(bad_sig, key, CodecOptions.SkipSignatureVerification, null, out decoded, out skip_error), skip_error);
        Assert.True(crypto.DecodePkiMessage(bad_sig, key, CodecOptions.LenientParsing, null, out decoded, out lenient_error), lenient_error);
    }

    // A SHA-1-signed response: FAILS under Strict (legacy digest), SUCCEEDS with AllowLegacyAlgorithms or
    // LenientParsing. The signature itself is valid, so only the legacy-algorithm gate trips.
    [Fact]
    public void Legacy_digest_fails_strict_but_passes_when_relaxed() {
        BouncyCastleScepCrypto crypto;
        IScepKey key;
        byte[] sha1_rep;
        PkiMessage decoded;
        string strict_error;
        string allow_error;
        string lenient_error;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out KeySpec spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        sha1_rep = BuildFailureCertRep("SHA1WITHRSA", use_wrong_signing_key: false);

        Assert.False(crypto.DecodePkiMessage(sha1_rep, key, CodecOptions.Strict, null, out decoded, out strict_error));
        Assert.Contains("legacy", strict_error.ToLowerInvariant());

        Assert.True(crypto.DecodePkiMessage(sha1_rep, key, CodecOptions.AllowLegacyAlgorithms, null, out decoded, out allow_error), allow_error);
        Assert.True(crypto.DecodePkiMessage(sha1_rep, key, CodecOptions.LenientParsing, null, out decoded, out lenient_error), lenient_error);
    }

    // Builds a signed (but NOT enveloped) failure CertRep with a chosen signature algorithm and, optionally,
    // a wrong signing key so the CMS signature does not verify. A failure CertRep has no encrypted content,
    // so Decode exercises only the signature/digest gates — exactly what these flags govern.
    private static byte[] BuildFailureCertRep(string signature_algorithm, bool use_wrong_signing_key) {
        RsaKeyPairGenerator gen;
        AsymmetricCipherKeyPair signer_pair;
        Org.BouncyCastle.X509.X509V3CertificateGenerator cg;
        Org.BouncyCastle.Asn1.X509.X509Name name;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        AsymmetricKeyParameter signing_key;
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;
        Dictionary<DerObjectIdentifier, object> attrs;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        CmsSignedDataGenerator signed_gen;
        SignerInfoGenerator signer_info;
        CmsSignedData signed_data;

        gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        signer_pair = gen.GenerateKeyPair();

        name = new Org.BouncyCastle.Asn1.X509.X509Name("CN=Fake CertRep Signer");
        cg = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
        cg.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(System.DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(System.DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(signer_pair.Public);
        signer_cert = cg.Generate(new Asn1SignatureFactory(signature_algorithm, signer_pair.Private));

        if (use_wrong_signing_key) {
            RsaKeyPairGenerator wrong_gen;
            AsymmetricCipherKeyPair wrong_pair;

            wrong_gen = new RsaKeyPairGenerator();
            wrong_gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            wrong_pair = wrong_gen.GenerateKeyPair();
            signing_key = wrong_pair.Private;
        } else {
            signing_key = signer_pair.Private;
        }

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();

        attrs = new Dictionary<DerObjectIdentifier, object>();
        attrs[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString("3")));
        attrs[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString("2")));
        attrs[new DerObjectIdentifier(OidFailInfo)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidFailInfo), new DerSet(new DerPrintableString("2")));
        attrs[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString("tx")));
        attrs[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(new byte[16])));

        cert_store = CollectionUtilities.CreateStore(new[] { signer_cert });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signer_info = new SignerInfoGeneratorBuilder()
            .WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attrs)))
            .Build(new Asn1SignatureFactory(signature_algorithm, signing_key), signer_cert);
        signed_gen.AddSignerInfoGenerator(signer_info);
        signed_gen.AddCertificates(cert_store);
        signed_data = signed_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), true);
        return signed_data.GetEncoded();
    }
}
