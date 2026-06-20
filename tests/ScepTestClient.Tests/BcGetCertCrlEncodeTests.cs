using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcGetCertCrlEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    private static CmsSignedData EncodeAndParse(MessageType type, string serial_hex, out byte[] inner_der, TestCa ca) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey signer_key;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        CmsEnvelopedData enveloped;
        MemoryStream ms;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out signer_key, out _);

        pki = new PkiMessage {
            MessageType = type,
            IssuerName = ca.Certificate.SubjectDN.ToString(),
            SerialNumber = serial_hex,
            SignerKey = signer_key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);
        signed = new CmsSignedData(der);

        ms = new MemoryStream();
        signed.SignedContent.Write(ms);
        enveloped = new CmsEnvelopedData(ms.ToArray());
        inner_der = enveloped.GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(ca.KeyPair.Private);
        return signed;
    }

    [Fact]
    public void Encodes_getcert_with_issuer_and_serial() {
        TestCa ca;
        CmsSignedData signed;
        byte[] inner_der;
        SignerInformation signer;
        IssuerAndSerialNumber ias;

        ca = TestCa.Create();
        signed = EncodeAndParse(MessageType.GetCert, "0A", out inner_der, ca);

        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal("21", ((DerPrintableString)signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)].AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);

        ias = IssuerAndSerialNumber.GetInstance(Asn1Object.FromByteArray(inner_der));
        Assert.Equal(10, ias.SerialNumber.Value.IntValue);
    }

    [Fact]
    public void Encodes_getcrl_message_type_22() {
        TestCa ca;
        CmsSignedData signed;
        byte[] inner_der;
        SignerInformation signer;

        ca = TestCa.Create();
        signed = EncodeAndParse(MessageType.GetCrl, "01", out inner_der, ca);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal("22", ((DerPrintableString)signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)].AttrValues[0]).GetString());
    }
}
