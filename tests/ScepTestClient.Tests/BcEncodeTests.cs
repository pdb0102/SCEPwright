using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    [Fact]
    public void Encodes_pkcsreq_signeddata_over_envelopeddata() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute msg_type;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=poodle", out _);

        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        msg_type = signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)];
        Assert.Equal("19", ((DerPrintableString)msg_type.AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);
    }

    [Fact]
    public void Encodes_pkcsreq_honors_digest_algorithm_oid() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        string expected_oid;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=digest-test", out _);

        expected_oid = Algorithms.OidFor("SHA-512")!;
        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
            DigestAlgorithmOid = expected_oid,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal(expected_oid, signer.DigestAlgOid);
    }
}
