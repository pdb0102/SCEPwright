using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcCsrBuilder {
    private const string ChallengePasswordOid = "1.2.840.113549.1.9.7";
    private const string ExtensionRequestOid = "1.2.840.113549.1.9.14";
    private const string SidExtensionOid = "1.3.6.1.4.1.311.25.2";
    private const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";

    public static byte[] Build(Pkcs10 csr, BcKey key) {
        X509Name subject;
        Org.BouncyCastle.Crypto.ISignatureFactory signer;
        List<Asn1Encodable> attributes;
        X509Extensions extensions;
        Asn1Set attribute_set;
        Pkcs10CertificationRequest request;

        subject = new X509Name(csr.Subject);
        signer = BcPqKeys.IsPq(key)
            ? BcPqKeys.SignatureFactory(key)
            : new Asn1SignatureFactory("SHA256WITHRSA", key.KeyPair.Private);
        attributes = new List<Asn1Encodable>();

        if (!string.IsNullOrEmpty(csr.ChallengePassword)) {
            attributes.Add(new AttributePkcs(new DerObjectIdentifier(ChallengePasswordOid), new DerSet(new DerPrintableString(csr.ChallengePassword))));
        }

        extensions = BuildExtensions(csr);
        if (extensions is not null) {
            attributes.Add(new AttributePkcs(new DerObjectIdentifier(ExtensionRequestOid), new DerSet(extensions)));
        }

        attribute_set = new DerSet(attributes.ToArray());
        request = new Pkcs10CertificationRequest(signer, subject, key.KeyPair.Public, attribute_set);
        return request.GetEncoded();
    }

    private static X509Extensions BuildExtensions(Pkcs10 csr) {
        X509ExtensionsGenerator gen;
        List<GeneralName> sans;
        bool any;

        gen = new X509ExtensionsGenerator();
        sans = new List<GeneralName>();
        any = false;

        foreach (string dns in csr.DnsNames) {
            sans.Add(new GeneralName(GeneralName.DnsName, dns));
        }

        foreach (string upn in csr.Upns) {
            sans.Add(new GeneralName(GeneralName.OtherName, new DerSequence(new DerObjectIdentifier(UpnOtherNameOid), new DerTaggedObject(true, 0, new DerUtf8String(upn)))));
        }

        if (sans.Count > 0) {
            gen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sans.ToArray()));
            any = true;
        }

        if (!string.IsNullOrEmpty(csr.Sid)) {
            DerOctetString sid_value;
            DerSequence sid_seq;

            sid_value = new DerOctetString(System.Text.Encoding.ASCII.GetBytes(csr.Sid!));
            sid_seq = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.25.2.1"), new DerTaggedObject(true, 0, sid_value));
            gen.AddExtension(new DerObjectIdentifier(SidExtensionOid), false, new DerSequence(sid_seq));
            any = true;
        }

        foreach ((string oid, byte[] value, bool critical) in csr.Extensions) {
            gen.AddExtension(new DerObjectIdentifier(oid), critical, value);
            any = true;
        }

        if (csr.AltKey is BcKey alt_bc) {
            Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo alt_spki;

            // subjectAltPublicKeyInfo (id-ce-subjectAltPublicKeyInfo, 2.5.29.72). Carries the alt public
            // key only; the built-in provider does NOT compute altSignatureAlgorithm/altSignatureValue
            // (bleeding-edge). Mainline X509.SubjectPublicKeyInfoFactory handles both classical and the
            // mainline PQ key types (Pqc.PqcSubjectPublicKeyInfoFactory throws for the latter).
            alt_spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(alt_bc.KeyPair.Public);
            gen.AddExtension(new DerObjectIdentifier("2.5.29.72"), false, alt_spki);
            any = true;
        }

        return any ? gen.Generate() : null!;
    }
}
