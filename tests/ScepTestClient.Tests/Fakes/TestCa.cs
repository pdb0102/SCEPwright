using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace ScepTestClient.Tests.Fakes;

public sealed class TestCa {
    public AsymmetricCipherKeyPair KeyPair { get; }
    public Org.BouncyCastle.X509.X509Certificate Certificate { get; }
    public X509Certificate2 CertificateBcl { get; }

    private readonly Dictionary<string, Org.BouncyCastle.X509.X509Certificate> _issued_by_serial = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>();

    public bool PendingMode { get; set; }
    public string? ExpectedChallenge { get; set; }

    private TestCa(AsymmetricCipherKeyPair keyPair, Org.BouncyCastle.X509.X509Certificate cert) {
        KeyPair = keyPair;
        Certificate = cert;
        CertificateBcl = new X509Certificate2(cert.GetEncoded());
    }

    public static TestCa Create() {
        RsaKeyPairGenerator gen;
        AsymmetricCipherKeyPair pair;
        X509V3CertificateGenerator cg;
        X509Name name;

        gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        pair = gen.GenerateKeyPair();

        name = new X509Name("CN=Test SCEP CA");
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        cg.SetPublicKey(pair.Public);

        return new TestCa(pair, cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", pair.Private)));
    }

    public Org.BouncyCastle.X509.X509Certificate Issue(AsymmetricKeyParameter subject_public_key, string subject_dn) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(subject_public_key);

        Org.BouncyCastle.X509.X509Certificate issued;
        issued = cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
        _issued_by_serial[issued.SerialNumber.ToString(16).ToUpperInvariant()] = issued;
        return issued;
    }

    public Org.BouncyCastle.X509.X509Certificate IssueExpired(AsymmetricKeyParameter subject_public_key, string subject_dn) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(DateTime.UtcNow.AddYears(-2));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(-1));
        cg.SetPublicKey(subject_public_key);
        return cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
    }

    // Builds a SUCCESS CertRep: SignedData (signed by CA) whose content is EnvelopedData (to the recipient cert)
    // of a degenerate PKCS#7 carrying the issued cert. Signed attrs: pkiStatus=0, messageType=3 (CertRep),
    // transId echoed, recipientNonce echoes the request senderNonce (pass any 16 bytes).
    public byte[] BuildSuccessCertRep(Org.BouncyCastle.X509.X509Certificate issued_cert, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        IStore<Org.BouncyCastle.X509.X509Certificate> issued_cert_store;
        byte[] degenerate_bytes;

        issued_cert_store = CollectionUtilities.CreateStore(new[] { issued_cert });
        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCertificates(issued_cert_store);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }

    // Builds a PENDING CertRep: pkiStatus=3, messageType=3 (CertRep), no issued cert (empty degenerate PKCS#7).
    public byte[] BuildPendingCertRep(X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "3");
    }

    public Org.BouncyCastle.X509.X509Crl GenerateCrl() {
        X509V2CrlGenerator crl_gen;

        crl_gen = new X509V2CrlGenerator();
        crl_gen.SetIssuerDN(Certificate.SubjectDN);
        crl_gen.SetThisUpdate(DateTime.UtcNow.AddMinutes(-5));
        crl_gen.SetNextUpdate(DateTime.UtcNow.AddDays(7));
        crl_gen.AddCrlEntry(BigInteger.ValueOf(99), DateTime.UtcNow.AddMinutes(-1), Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise);
        return crl_gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
    }

    public byte[] BuildSuccessCrlRep(Org.BouncyCastle.X509.X509Crl crl, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCrl(crl);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }

    public byte[] BuildFailureCertRep(X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string fail_info) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidFailInfo = "2.16.840.1.113733.1.9.4";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;
        Dictionary<DerObjectIdentifier, object> attrs;
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsSignedData signed_data;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();

        attrs = new Dictionary<DerObjectIdentifier, object>();
        attrs[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString("3")));
        attrs[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString("2")));
        attrs[new DerObjectIdentifier(OidFailInfo)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidFailInfo), new DerSet(new DerPrintableString(fail_info)));
        attrs[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        attrs[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSigner(KeyPair.Private, Certificate, CmsSignedGenerator.DigestSha256, new Org.BouncyCastle.Asn1.Cms.AttributeTable(attrs), null);
        signed_gen.AddCertificates(ca_cert_store);
        signed_data = signed_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), true);
        return signed_data.GetEncoded();
    }

    private byte[] EnvelopeAndSign(byte[] degenerate_bytes, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string message_type, string pki_status) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

        Org.BouncyCastle.X509.X509Certificate recipient_bc_cert;
        CmsEnvelopedDataGenerator enveloped_gen;
        CmsEnvelopedData enveloped;
        byte[] enveloped_bytes;
        Dictionary<DerObjectIdentifier, object> signed_attrs_dict;
        Org.BouncyCastle.Asn1.Cms.AttributeTable signed_attr_table;
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsProcessable enveloped_content;
        CmsSignedData signed_data;

        recipient_bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(recipient_cert.RawData);
        enveloped_gen = new CmsEnvelopedDataGenerator(new SecureRandom());
        enveloped_gen.AddKeyTransRecipient(recipient_bc_cert);
        enveloped = enveloped_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), CmsEnvelopedGenerator.Aes128Cbc);
        enveloped_bytes = enveloped.GetEncoded();

        signed_attrs_dict = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs_dict[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString(message_type)));
        signed_attrs_dict[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString(pki_status)));
        signed_attrs_dict[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs_dict[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));
        signed_attr_table = new Org.BouncyCastle.Asn1.Cms.AttributeTable(signed_attrs_dict);

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSigner(KeyPair.Private, Certificate, CmsSignedGenerator.DigestSha256, signed_attr_table, null);
        signed_gen.AddCertificates(ca_cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped_bytes);
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.EnvelopedData.Id, enveloped_content, true);
        return signed_data.GetEncoded();
    }

    // Server side: decrypt the PKCSReq, issue a cert for the enclosed CSR, return a SUCCESS CertRep
    // enveloped back to the request's signer certificate (which wraps the client's key).
    // A priority ladder runs first, answering the RFC-expected failInfo for each detectable fault.
    public byte[] HandlePkiOperation(byte[] pkcs_req_der) {
        CmsSignedData signed;
        SignerInformation signer;
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] sender_nonce;
        byte[] inner_payload;
        System.DateTime? signing_time;

        signed = new CmsSignedData(pkcs_req_der);
        signer = First(signed);

        // 1. Signature integrity -> badMessageCheck ("1").
        if (!VerifyOuterSignature(pkcs_req_der)) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "1");
        }

        // 2. signingTime window (+-5 min) -> badTime ("3").
        signing_time = ReadSigningTime(pkcs_req_der);
        if (signing_time.HasValue && System.Math.Abs((DateTime.UtcNow - signing_time.Value).TotalMinutes) > 5) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "3");
        }

        // 3. Forbidden digest (MD5) -> badAlg ("0").
        if (signer.DigestAlgOid == "1.2.840.113549.2.5") {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "0");
        }

        // 4. Inner CSR must parse -> badRequest ("2").
        if (!InnerCsrParses(pkcs_req_der)) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "2");
        }

        DecodeRequest(pkcs_req_der, out requester_cert, out trans_id, out sender_nonce, out inner_payload);

        // 5. Expected challenge -> FAILURE with badRequest ("2").
        if (ExpectedChallenge != null && ChallengeFrom(inner_payload) != ExpectedChallenge) {
            return BuildFailureCertRep(requester_cert, trans_id, sender_nonce, "2");
        }

        // 6. Expired signer cert (mirror a real CA refusing to renew off an expired cert).
        if (SignerCertExpired(requester_cert)) {
            return BuildFailureCertRep(requester_cert, trans_id, sender_nonce, "2");
        }

        // 7. PENDING mode.
        if (PendingMode) {
            return BuildPendingCertRep(requester_cert, trans_id, sender_nonce);
        }

        // Success (existing issue path).
        return IssueAndBuildSuccess(inner_payload, requester_cert, trans_id, sender_nonce);
    }

    private X509Certificate2 RecipientFrom(CmsSignedData signed, SignerInformation signer) {
        return new X509Certificate2(FirstCert(signed, signer).GetEncoded());
    }

    private static string TransIdFrom(SignerInformation signer) {
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;
        Org.BouncyCastle.Asn1.Cms.Attribute? tx_a;

        attrs = signer.SignedAttributes;
        if (attrs is null) { return "tx"; }
        tx_a = attrs[new DerObjectIdentifier(OidTransId)];
        if (tx_a is null) { return "tx"; }
        return ((DerPrintableString)tx_a.AttrValues[0]).GetString();
    }

    private static byte[] NonceFrom(SignerInformation signer) {
        const string OidSenderNonce = "2.16.840.1.113733.1.9.5";
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;
        Org.BouncyCastle.Asn1.Cms.Attribute? n_a;

        attrs = signer.SignedAttributes;
        if (attrs is null) { return new byte[16]; }
        n_a = attrs[new DerObjectIdentifier(OidSenderNonce)];
        if (n_a is null) { return new byte[16]; }
        return ((Asn1OctetString)n_a.AttrValues[0]).GetOctets();
    }

    private static string ChallengeFrom(byte[] csr_der) {
        const string OidChallengePassword = "1.2.840.113549.1.9.7";
        Pkcs10CertificationRequest csr;
        CertificationRequestInfo info;
        Asn1Set attributes;

        csr = new Pkcs10CertificationRequest(csr_der);
        info = csr.GetCertificationRequestInfo();
        attributes = info.Attributes;
        if (attributes is null) { return string.Empty; }

        foreach (Asn1Encodable encodable in attributes) {
            AttributePkcs attr;

            attr = AttributePkcs.GetInstance(encodable);
            if (attr.AttrType.Id == OidChallengePassword && attr.AttrValues.Count > 0) {
                return ((IAsn1String)attr.AttrValues[0]).GetString();
            }
        }
        return string.Empty;
    }

    private static bool SignerCertExpired(X509Certificate2 signer_cert) {
        return signer_cert.NotAfter < DateTime.UtcNow;
    }

    private byte[] IssueAndBuildSuccess(byte[] csr_der, X509Certificate2 requester_cert, string trans_id, byte[] sender_nonce) {
        Pkcs10CertificationRequest csr;
        AsymmetricKeyParameter csr_public_key;
        string subject_dn;
        Org.BouncyCastle.X509.X509Certificate issued;

        csr = new Pkcs10CertificationRequest(csr_der);
        csr_public_key = csr.GetPublicKey();
        subject_dn = csr.GetCertificationRequestInfo().Subject.ToString();

        issued = Issue(csr_public_key, subject_dn);
        return BuildSuccessCertRep(issued, requester_cert, trans_id, sender_nonce);
    }

    public bool VerifyOuterSignature(byte[] der) {
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate signer_cert;

        signed = new CmsSignedData(der);
        signer = First(signed);
        signer_cert = FirstCert(signed, signer);
        try {
            return signer.Verify(signer_cert.GetPublicKey());
        } catch (System.Exception) {
            return false;
        }
    }

    public System.DateTime? ReadSigningTime(byte[] der) {
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute? attr;

        signed = new CmsSignedData(der);
        signer = First(signed);
        if (signer.SignedAttributes == null) { return null; }
        attr = signer.SignedAttributes[new DerObjectIdentifier("1.2.840.113549.1.9.5")];
        if (attr == null) { return null; }
        return Org.BouncyCastle.Asn1.Cms.Time.GetInstance(attr.AttrValues[0]).ToDateTime();
    }

    public bool InnerCsrParses(byte[] der) {
        byte[] inner;
        Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest parsed;

        try {
            inner = DecryptInner(der);
            parsed = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(inner);
            return parsed.Verify();
        } catch (System.Exception) {
            return false;
        }
    }

    private static SignerInformation First(CmsSignedData signed) {
        return signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
    }

    private static Org.BouncyCastle.X509.X509Certificate FirstCert(CmsSignedData signed, SignerInformation signer) {
        return signed.GetCertificates().EnumerateMatches(signer.SignerID).Cast<Org.BouncyCastle.X509.X509Certificate>().First();
    }

    private byte[] DecryptInner(byte[] der) {
        CmsSignedData signed;
        MemoryStream env_stream;
        CmsEnvelopedData env;

        signed = new CmsSignedData(der);
        env_stream = new MemoryStream();
        signed.SignedContent.Write(env_stream);
        env = new CmsEnvelopedData(env_stream.ToArray());
        return env.GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(KeyPair.Private);
    }

    public string PeekMessageType(byte[] der) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute? attr;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        attr = signer.SignedAttributes?[new DerObjectIdentifier(OidMessageType)];
        return attr is null ? string.Empty : ((DerPrintableString)attr.AttrValues[0]).GetString();
    }

    public byte[] HandleGetCert(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;
        Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber ias;
        string serial_key;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);
        ias = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber.GetInstance(Asn1Object.FromByteArray(inner));
        serial_key = ias.SerialNumber.Value.ToString(16).ToUpperInvariant();

        if (!_issued_by_serial.TryGetValue(serial_key, out Org.BouncyCastle.X509.X509Certificate? found)) {
            return BuildFailureCertRep(requester_cert, trans_id, nonce, "4");
        }
        return BuildSuccessCertRep(found, requester_cert, trans_id, nonce);
    }

    public byte[] HandleGetCrl(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);
        return BuildSuccessCrlRep(GenerateCrl(), requester_cert, trans_id, nonce);
    }

    private void DecodeRequest(byte[] der, out X509Certificate2 requester_cert, out string trans_id, out byte[] sender_nonce, out byte[] inner_payload) {
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidSenderNonce = "2.16.840.1.113733.1.9.5";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate signer_bc_cert;
        MemoryStream env_stream;
        CmsEnvelopedData env;
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        signer_bc_cert = signed.GetCertificates().EnumerateMatches(signer.SignerID).Cast<Org.BouncyCastle.X509.X509Certificate>().First();
        requester_cert = new X509Certificate2(signer_bc_cert.GetEncoded());

        env_stream = new MemoryStream();
        signed.SignedContent.Write(env_stream);
        env = new CmsEnvelopedData(env_stream.ToArray());
        inner_payload = env.GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(KeyPair.Private);

        trans_id = "tx";
        sender_nonce = new byte[16];
        attrs = signer.SignedAttributes;
        if (attrs is not null) {
            Org.BouncyCastle.Asn1.Cms.Attribute? tx_a = attrs[new DerObjectIdentifier(OidTransId)];
            Org.BouncyCastle.Asn1.Cms.Attribute? n_a = attrs[new DerObjectIdentifier(OidSenderNonce)];
            if (tx_a is not null) { trans_id = ((DerPrintableString)tx_a.AttrValues[0]).GetString(); }
            if (n_a is not null) { sender_nonce = ((Asn1OctetString)n_a.AttrValues[0]).GetOctets(); }
        }
    }

    public byte[] HandlePoll(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;
        Asn1Sequence ias;
        Org.BouncyCastle.Asn1.X509.X509Name subject_name;
        Org.BouncyCastle.X509.X509Certificate issued;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);

        if (PendingMode) {
            return BuildPendingCertRep(requester_cert, trans_id, nonce);
        }

        ias = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(inner));
        subject_name = Org.BouncyCastle.Asn1.X509.X509Name.GetInstance(ias[1]);

        issued = Issue(new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(requester_cert.RawData).GetPublicKey(), subject_name.ToString());
        return BuildSuccessCertRep(issued, requester_cert, trans_id, nonce);
    }
}
