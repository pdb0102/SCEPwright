using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcRenewalEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    [Fact]
    public void Encodes_renewalreq_signed_with_existing_cert() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey existing_key;
        IScepKey new_key;
        X509Certificate2 existing_cert;
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
        crypto.GenerateKey(spec, out existing_key, out _);
        crypto.GenerateKey(spec, out new_key, out _);

        existing_cert = new X509Certificate2(
            ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

        csr = new Pkcs10 { Key = new_key };
        csr.SetSubject("CN=poodle", out _);

        pki = new PkiMessage {
            MessageType = MessageType.RenewalReq,
            InnerCsr = csr,
            SignerKey = existing_key,
            SignerCert = existing_cert,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        msg_type = signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)];
        Assert.Equal("17", ((DerPrintableString)msg_type.AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);
    }
}
