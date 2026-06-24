using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using ScepWright.Crypto;

namespace ScepWright.Crypto.BouncyCastle;

internal static class BcPkiMessage {
    private static readonly SecureRandom Random = new SecureRandom();

    private const string SigningTimeOid = "1.2.840.113549.1.9.5";

    public static byte[] EncodePkiOperation(PkiMessage message, byte[] inner_payload_der, BcKey signer_key, string message_type_number, FaultDirectives? faults) {
        CmsProcessable enveloped_content;
        byte[] enveloped_bytes;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        CmsSignedDataGenerator signed_gen;
        Dictionary<DerObjectIdentifier, object> signed_attrs;
        AttributeTable signed_attr_table;
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        string trans_id;
        byte[] sender_nonce;
        byte[] payload_for_envelope;
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter signing_private_key;

        if (message.SignerCert != null) {
            signer_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(message.SignerCert.RawData);
        } else {
            signer_cert = BcSelfSigned.ForKey(signer_key, "CN=SCEP-Client");
        }

        trans_id = message.TransactionId ?? Guid.NewGuid().ToString("N");
        message.TransactionId = trans_id;

        // Honor a caller-supplied senderNonce (lets a conformance probe replay an identical message);
        // otherwise mint a fresh 16-byte nonce. Either way, write it back so the caller can later match
        // it against the response's recipientNonce (RFC 8894 §3.2.1.1 requires the server to echo it).
        if (message.SenderNonce != null && message.SenderNonce.Length > 0) {
            sender_nonce = message.SenderNonce;
        } else {
            sender_nonce = new byte[16];
            Random.NextBytes(sender_nonce);
        }
        message.SenderNonce = sender_nonce;

        signed_attrs = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs[new DerObjectIdentifier(ScepAttributes.MessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.MessageType), new DerSet(new DerPrintableString(message_type_number)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.TransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.TransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.SenderNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.SenderNonce), new DerSet(new DerOctetString(sender_nonce)));
        signed_attr_table = new AttributeTable(signed_attrs);

        payload_for_envelope = inner_payload_der;
        signing_private_key = signer_key.KeyPair.Private;

        // ---- BEGIN deliberate-fault branch (delete to make production-pure) ----
        if (faults != null) {
            if (faults.CorruptInnerContent) {
                payload_for_envelope = (byte[])inner_payload_der.Clone();
                for (int i = 0; i < payload_for_envelope.Length; i++) {
                    payload_for_envelope[i] ^= 0xFF;
                }
            }
            if (faults.CorruptSignature) {
                Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator throwaway_gen;
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair throwaway;

                throwaway_gen = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
                throwaway_gen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(Random, 2048));
                throwaway = throwaway_gen.GenerateKeyPair();
                signing_private_key = throwaway.Private;
            }
            if (faults.SigningTimeSkew.HasValue) {
                signed_attrs[new DerObjectIdentifier(SigningTimeOid)] = new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(SigningTimeOid),
                    new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(System.DateTime.UtcNow.Add(faults.SigningTimeSkew.Value), 2049))));
                signed_attr_table = new AttributeTable(signed_attrs);
            }
        }
        // ---- END deliberate-fault branch ----

        enveloped_bytes = BcEnvelope.Build(message.RecipientCaCert!, payload_for_envelope, message.ContentEncryptionAlgorithmOid, Random);

        cert_store = CollectionUtilities.CreateStore(new[] { signer_cert });
        signed_gen = new CmsSignedDataGenerator(Random);
        if (signing_private_key is Org.BouncyCastle.Crypto.Parameters.MLDsaPrivateKeyParameters
            || signing_private_key is Org.BouncyCastle.Crypto.Parameters.SlhDsaPrivateKeyParameters) {
            // PQ outer signature (BC 2.6.1): the legacy AddSigner overloads can't sign with ML-DSA/SLH-DSA;
            // use the SignerInfoGeneratorBuilder path. Digest is the draft baseline (SHA-512), picked by BC.
            Org.BouncyCastle.Cms.SignerInfoGenerator pq_signer;

            pq_signer = new Org.BouncyCastle.Cms.SignerInfoGeneratorBuilder()
                .WithSignedAttributeGenerator(new Org.BouncyCastle.Cms.DefaultSignedAttributeTableGenerator(signed_attr_table))
                .Build(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(signer_key.AlgorithmOid, signing_private_key, Random), signer_cert);
            signed_gen.AddSignerInfoGenerator(pq_signer);
        } else {
            signed_gen.AddSigner(signing_private_key, signer_cert, message.DigestAlgorithmOid, signed_attr_table, null);
        }
        signed_gen.AddCertificates(cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped_bytes);
        // RFC 8894 §3.2: the SignedData encapContentInfo eContentType MUST be id-data (the inner
        // pkcsPKIEnvelope carries its own envelopedData ContentInfo). CMS (RFC 5652 §11.1) then forces
        // the content-type signed attribute to match, so id-data here makes both conformant.
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.Data.Id, enveloped_content, true);

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

    public static byte[] BuildIssuerAndSubject(string issuer_dn, string subject_dn) {
        Org.BouncyCastle.Asn1.X509.X509Name issuer;
        Org.BouncyCastle.Asn1.X509.X509Name subject;
        DerSequence seq;

        issuer = new Org.BouncyCastle.Asn1.X509.X509Name(issuer_dn);
        subject = new Org.BouncyCastle.Asn1.X509.X509Name(subject_dn);
        seq = new DerSequence(issuer, subject);
        return seq.GetDerEncoded();
    }

    private const string Md5DigestOid = "1.2.840.113549.2.5";
    private const string Sha1DigestOid = "1.3.14.3.2.26";

    public static PkiMessage Decode(byte[] der, BcKey recipient_key, CodecOptions options) {
        return Decode(der, recipient_key, options, known_certs: null, out _);
    }

    // Honors CodecOptions. Strict (0) enforces both a valid CMS signature and a non-legacy signer digest;
    // SkipSignatureVerification relaxes the first gate, AllowLegacyAlgorithms the second, and
    // LenientParsing relaxes both (today's tolerant behavior). On a strict-mode violation the message is
    // still returned (so callers can inspect it), but decode_error is set non-empty so the provider can
    // surface a clean false + error.
    public static PkiMessage Decode(byte[] der, BcKey recipient_key, CodecOptions options,
                                    System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>? known_certs, out string decode_error) {
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        ICollection<SignerInformation> signer_collection;
        System.Collections.IEnumerator signer_enumerator;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate? embedded_match;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        string verified_source;
        int candidate_count;
        bool signature_ok;
        bool lenient;
        string digest_oid;
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

        decode_error = string.Empty;
        lenient = (options & CodecOptions.LenientParsing) != 0;

        result = new PkiMessage { MessageType = MessageType.CertRep };
        signed_data = new CmsSignedData(der);
        cert_store = signed_data.GetCertificates();

        // --- Signature verification ---
        signer_collection = (ICollection<SignerInformation>)signed_data.GetSignerInfos().GetSigners();
        signer_enumerator = ((System.Collections.IEnumerable)signer_collection).GetEnumerator();
        signer_enumerator.MoveNext();
        signer = (SignerInformation)signer_enumerator.Current;

        // Record who the response *claims* signed it (issuer+serial or subjectKeyIdentifier), so a failed
        // verification can be diagnosed: genuinely invalid vs. "the signer cert wasn't where we looked".
        result.SignerClaimedIdentity = FormatSignerId(signer.SignerID);

        // The cert the CertRep itself offered for the claimed signer (matched by SignerIdentifier).
        embedded_match = null;
        foreach (Org.BouncyCastle.X509.X509Certificate c in cert_store.EnumerateMatches(signer.SignerID)) {
            embedded_match = c;
            break;
        }

        // Verify against a candidate pool — the CertRep's own certs first, then the GetCACert bundle — so a
        // valid signature whose signer cert was simply not embedded is confirmed, and a "claimed cert X but
        // cert Y actually signed" mismatch is detected rather than reported as a bare failure.
        signature_ok = false;
        signer_cert = null!;
        verified_source = string.Empty;
        candidate_count = 0;
        if (embedded_match != null && TryVerify(signer, embedded_match)) {
            signature_ok = true;
            signer_cert = embedded_match;
            verified_source = "CertRep";
        } else {
            foreach (System.ValueTuple<Org.BouncyCastle.X509.X509Certificate, string> candidate in VerificationCandidates(cert_store, known_certs)) {
                candidate_count++;
                if (!signature_ok && TryVerify(signer, candidate.Item1)) {
                    signature_ok = true;
                    signer_cert = candidate.Item1;
                    verified_source = candidate.Item2;
                }
            }
        }

        result.SignatureValid = signature_ok;
        if (signature_ok && (verified_source != "CertRep" || !ReferenceEquals(signer_cert, embedded_match))) {
            // Verified, but not by the cert the CertRep presented for the claimed signer — surface what
            // actually signed, since a peer relying on the CertRep's own bag would call this invalid.
            result.SignerVerifiedWith = $"{DescribeCert(signer_cert)} (from {verified_source})";
            result.ConformanceNotes.Add(new ConformanceNote(NoteSeverity.Warning,
                $"signature is VALID but was verified using the {verified_source} cert [{DescribeCert(signer_cert)}], not the cert the CertRep presented for the claimed signer ({result.SignerClaimedIdentity})"
                    + (embedded_match == null
                        ? " — the CertRep embedded no cert matching the claimed signer; the server should include its RA/CA signing cert in the CertRep"
                        : $" — the embedded cert [{DescribeCert(embedded_match)}] did not verify the signature"),
                "SignedData", "RFC 8894 §3.2"));
        } else if (signature_ok) {
            result.SignerVerifiedWith = $"{DescribeCert(signer_cert)} (from CertRep)";
        } else {
            // Nothing verified: report the claimed signer, the cert we checked, and how many we tried, so a
            // server-implementor can tell a truly bad signature from a wrong-cert / missing-cert situation.
            result.SignerVerifiedWith = null;
            result.ConformanceNotes.Add(new ConformanceNote(NoteSeverity.Warning,
                $"signature verification FAILED — claimed signer: {result.SignerClaimedIdentity}; "
                    + (embedded_match != null
                        ? $"the cert the CertRep presented for that signer [{DescribeCert(embedded_match)}] did not verify; "
                        : "no cert embedded in the CertRep matched the claimed signer; ")
                    + $"tried {candidate_count} candidate cert(s) from the CertRep bag and the GetCACert bundle and none produced a valid signature — the signature is invalid against every available cert (wrong signing key, altered message, or the real signing cert was provided by neither GetCACert nor the CertRep)",
                "SignedData", "RFC 8894 §3.2"));
        }

        // Strict-mode gate 1 — signature integrity. Fail unless the caller opted into tolerance
        // (SkipSignatureVerification or LenientParsing). LenientParsing preserves today's behavior.
        if (!signature_ok && (options & CodecOptions.SkipSignatureVerification) == 0 && !lenient) {
            decode_error = "response signature verification failed";
        }

        // Strict-mode gate 2 — legacy signer digest (MD5 / SHA-1). Fail unless the caller opted into
        // tolerance (AllowLegacyAlgorithms or LenientParsing).
        digest_oid = signer.DigestAlgorithmID.Algorithm.Id;
        if ((digest_oid == Md5DigestOid || digest_oid == Sha1DigestOid)
                && (options & CodecOptions.AllowLegacyAlgorithms) == 0 && !lenient) {
            result.ConformanceNotes.Add(new ConformanceNote(NoteSeverity.Warning, "legacy signer digest algorithm (MD5/SHA-1)", "SignerInfo", "RFC 8894 §3.2"));
            if (decode_error.Length == 0) {
                decode_error = "response uses a legacy signer digest algorithm (MD5/SHA-1)";
            }
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
            string fail_info_str;

            fail_info_str = ((DerPrintableString)fail_info_attr.AttrValues[0]).GetString();
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
            result.IssuedCrls = ExtractCrlsFromDegeneratePkcs7(decrypted_bytes);
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

    private static bool TryVerify(SignerInformation signer, Org.BouncyCastle.X509.X509Certificate cert) {
        try {
            return signer.Verify(cert);
        } catch {
            return false;
        }
    }

    // The candidate certificates the response signature is checked against: every cert embedded in the
    // CertRep, then the caller-supplied GetCACert bundle (so a signer cert the server didn't embed is found).
    private static System.Collections.Generic.IEnumerable<System.ValueTuple<Org.BouncyCastle.X509.X509Certificate, string>> VerificationCandidates(
            IStore<Org.BouncyCastle.X509.X509Certificate> embedded,
            System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>? known_certs) {
        Org.BouncyCastle.X509.X509CertificateParser parser;

        foreach (Org.BouncyCastle.X509.X509Certificate c in embedded.EnumerateMatches(new Org.BouncyCastle.X509.Store.X509CertStoreSelector())) {
            yield return new System.ValueTuple<Org.BouncyCastle.X509.X509Certificate, string>(c, "CertRep");
        }
        if (known_certs != null) {
            parser = new Org.BouncyCastle.X509.X509CertificateParser();
            foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 kc in known_certs) {
                yield return new System.ValueTuple<Org.BouncyCastle.X509.X509Certificate, string>(parser.ReadCertificate(kc.RawData), "GetCACert");
            }
        }
    }

    // "issuer 'CN=..', serial 0A" for an issuerAndSerialNumber signer, or "subjectKeyIdentifier <hex>".
    private static string FormatSignerId(Org.BouncyCastle.Cms.SignerID id) {
        if (id.Issuer != null && id.SerialNumber != null) {
            return $"issuer '{id.Issuer}', serial {id.SerialNumber.ToString(16)}";
        }
        if (id.SubjectKeyIdentifier != null) {
            return $"subjectKeyIdentifier {Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(id.SubjectKeyIdentifier)}";
        }
        return "(unspecified signer identifier)";
    }

    private static string DescribeCert(Org.BouncyCastle.X509.X509Certificate cert) {
        return $"subject '{cert.SubjectDN}', serial {cert.SerialNumber.ToString(16)}";
    }

    private static IReadOnlyList<byte[]> ExtractCrlsFromDegeneratePkcs7(byte[] der) {
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Crl> crl_store;
        List<byte[]> crls;

        crls = new List<byte[]>();
        signed_data = new CmsSignedData(der);
        crl_store = signed_data.GetCrls();
        foreach (Org.BouncyCastle.X509.X509Crl crl in crl_store.EnumerateMatches(null)) {
            crls.Add(crl.GetEncoded());
        }

        return crls;
    }
}
