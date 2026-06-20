using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcPkiMessage {
    private static readonly SecureRandom Random = new SecureRandom();

    public static byte[] EncodePkiOperation(PkiMessage message, byte[] inner_payload_der, BcKey signer_key, string message_type_number) {
        CmsEnvelopedDataGenerator enveloped_gen;
        CmsEnvelopedData enveloped;
        CmsProcessable enveloped_content;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        CmsSignedDataGenerator signed_gen;
        Dictionary<DerObjectIdentifier, object> signed_attrs;
        AttributeTable signed_attr_table;
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        string trans_id;
        byte[] sender_nonce;
        Org.BouncyCastle.X509.X509Certificate recipient_bc_cert;

        recipient_bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(message.RecipientCaCert!.RawData);
        enveloped_gen = new CmsEnvelopedDataGenerator(Random);
        enveloped_gen.AddKeyTransRecipient(recipient_bc_cert);
        enveloped = enveloped_gen.Generate(new CmsProcessableByteArray(inner_payload_der), message.ContentEncryptionAlgorithmOid);

        if (message.SignerCert != null) {
            signer_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(message.SignerCert.RawData);
        } else {
            signer_cert = BcSelfSigned.ForKey(signer_key, "CN=SCEP-Client");
        }

        trans_id = message.TransactionId ?? Guid.NewGuid().ToString("N");
        message.TransactionId = trans_id;

        sender_nonce = new byte[16];
        Random.NextBytes(sender_nonce);

        signed_attrs = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs[new DerObjectIdentifier(ScepAttributes.MessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.MessageType), new DerSet(new DerPrintableString(message_type_number)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.TransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.TransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.SenderNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.SenderNonce), new DerSet(new DerOctetString(sender_nonce)));
        signed_attr_table = new AttributeTable(signed_attrs);

        cert_store = CollectionUtilities.CreateStore(new[] { signer_cert });
        signed_gen = new CmsSignedDataGenerator(Random);
        signed_gen.AddSigner(signer_key.KeyPair.Private, signer_cert, message.DigestAlgorithmOid, signed_attr_table, null);
        signed_gen.AddCertificates(cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped.GetEncoded());
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.EnvelopedData.Id, enveloped_content, true);

        return signed_data.GetEncoded();
    }

    public static byte[] BuildIssuerAndSerial(string issuer_dn, string serial_hex) {
        Org.BouncyCastle.Asn1.X509.X509Name issuer;
        Org.BouncyCastle.Math.BigInteger serial;
        IssuerAndSerialNumber ias;

        issuer = new Org.BouncyCastle.Asn1.X509.X509Name(issuer_dn);
        serial = new Org.BouncyCastle.Math.BigInteger(serial_hex, 16);
        ias = new IssuerAndSerialNumber(issuer, serial);
        return ias.GetDerEncoded();
    }

    public static PkiMessage Decode(byte[] der, BcKey recipient_key, CodecOptions options) {
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        ICollection<SignerInformation> signer_collection;
        System.Collections.IEnumerator signer_enumerator;
        SignerInformation signer;
        System.Collections.Generic.IEnumerable<Org.BouncyCastle.X509.X509Certificate> matching_certs;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        bool signature_ok;
        bool pki_status_present;
        Org.BouncyCastle.Asn1.Cms.Attribute pki_status_attr;
        Org.BouncyCastle.Asn1.Cms.Attribute fail_info_attr;
        Org.BouncyCastle.Asn1.Cms.Attribute recipient_nonce_attr;
        Org.BouncyCastle.Asn1.Cms.Attribute trans_id_attr;
        string pki_status_str;
        PkiMessage result;
        System.IO.MemoryStream enveloped_stream;
        byte[] enveloped_bytes;
        byte[] decrypted_bytes;
        List<X509Certificate2> issued_certs;

        result = new PkiMessage { MessageType = MessageType.CertRep };
        signed_data = new CmsSignedData(der);
        cert_store = signed_data.GetCertificates();

        // --- Signature verification ---
        signer_collection = (ICollection<SignerInformation>)signed_data.GetSignerInfos().GetSigners();
        signer_enumerator = ((System.Collections.IEnumerable)signer_collection).GetEnumerator();
        signer_enumerator.MoveNext();
        signer = (SignerInformation)signer_enumerator.Current;

        matching_certs = cert_store.EnumerateMatches(signer.SignerID);
        signer_cert = null!;
        foreach (Org.BouncyCastle.X509.X509Certificate c in matching_certs) {
            signer_cert = c;
            break;
        }

        signature_ok = false;
        if (signer_cert != null) {
            try {
                signature_ok = signer.Verify(signer_cert);
            } catch {
                signature_ok = false;
            }
        }

        result.SignatureValid = signature_ok;
        if (!signature_ok) {
            result.ConformanceNotes.Add(new ConformanceNote(NoteSeverity.Warning, "signature verification failed", "SignedData", "RFC 8894 §3.2"));
        }

        // --- Read signed attributes ---
        pki_status_attr = signer.SignedAttributes[new DerObjectIdentifier(ScepAttributes.PkiStatus)];
        pki_status_present = pki_status_attr != null;
        if (pki_status_present) {
            pki_status_str = ((DerPrintableString)pki_status_attr!.AttrValues[0]).GetString();
            result.PkiStatus = pki_status_str switch {
                "0" => PkiStatus.Success,
                "2" => PkiStatus.Failure,
                "3" => PkiStatus.Pending,
                _ => PkiStatus.Failure,
            };
        } else {
            result.ConformanceNotes.Add(new ConformanceNote(NoteSeverity.Warning, "pkiStatus attribute missing", "CertRep signed attributes", "RFC 8894 §3.2.1.2"));
        }

        fail_info_attr = signer.SignedAttributes[new DerObjectIdentifier(ScepAttributes.FailInfo)];
        if (fail_info_attr != null) {
            string fail_info_str = ((DerPrintableString)fail_info_attr.AttrValues[0]).GetString();
            result.FailInfo = fail_info_str switch {
                "0" => FailInfo.BadAlg,
                "1" => FailInfo.BadMessageCheck,
                "2" => FailInfo.BadRequest,
                "3" => FailInfo.BadTime,
                "4" => FailInfo.BadCertId,
                _ => FailInfo.None,
            };
        }

        recipient_nonce_attr = signer.SignedAttributes[new DerObjectIdentifier(ScepAttributes.RecipientNonce)];
        if (recipient_nonce_attr != null) {
            result.RecipientNonce = ((DerOctetString)recipient_nonce_attr.AttrValues[0]).GetOctets();
        }

        trans_id_attr = signer.SignedAttributes[new DerObjectIdentifier(ScepAttributes.TransId)];
        if (trans_id_attr != null) {
            result.TransactionId = ((DerPrintableString)trans_id_attr.AttrValues[0]).GetString();
        }

        // --- Decrypt EnvelopedData if Success ---
        if (pki_status_present && result.PkiStatus == PkiStatus.Success) {
            enveloped_stream = new System.IO.MemoryStream();
            signed_data.SignedContent.Write(enveloped_stream);
            enveloped_bytes = enveloped_stream.ToArray();
            decrypted_bytes = DecryptEnveloped(enveloped_bytes, recipient_key);
            result.DecryptedContent = decrypted_bytes;
            issued_certs = ExtractCertsFromDegeneratePkcs7(decrypted_bytes);
            result.IssuedCerts = issued_certs.AsReadOnly();
        }

        return result;
    }

    private static byte[] DecryptEnveloped(byte[] enveloped_der, BcKey recipient_key) {
        CmsEnvelopedData enveloped_data;
        RecipientInformationStore recipients;
        System.Collections.Generic.ICollection<RecipientInformation> recipient_infos;
        System.Collections.IEnumerator recipient_enumerator;
        RecipientInformation recipient;

        enveloped_data = new CmsEnvelopedData(enveloped_der);
        recipients = enveloped_data.GetRecipientInfos();
        recipient_infos = (System.Collections.Generic.ICollection<RecipientInformation>)recipients.GetRecipients();
        recipient_enumerator = ((System.Collections.IEnumerable)recipient_infos).GetEnumerator();
        recipient_enumerator.MoveNext();
        recipient = (RecipientInformation)recipient_enumerator.Current;

        return recipient.GetContent(recipient_key.KeyPair.Private);
    }

    private static List<X509Certificate2> ExtractCertsFromDegeneratePkcs7(byte[] der) {
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        List<X509Certificate2> certs;

        certs = new List<X509Certificate2>();
        signed_data = new CmsSignedData(der);
        cert_store = signed_data.GetCertificates();
        foreach (Org.BouncyCastle.X509.X509Certificate bc_cert in cert_store.EnumerateMatches(null)) {
            certs.Add(new X509Certificate2(bc_cert.GetEncoded()));
        }

        return certs;
    }
}
