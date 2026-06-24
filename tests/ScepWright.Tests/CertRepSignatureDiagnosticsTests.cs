using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.Collections;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// When a CertRep signature can't be verified the client must say WHO claimed to sign it and WHAT cert it
// checked — and try the GetCACert bundle — so a server-implementor can tell a genuinely invalid signature
// from "the signer cert simply wasn't embedded in the CertRep, so we looked in the wrong place".
public class CertRepSignatureDiagnosticsTests {
    private static byte[] BuildCertRep(out BouncyCastleScepCrypto crypto, out ScepCa ca, out IScepKey client_key) {
        KeySpec spec;
        Pkcs10 csr;
        byte[] csr_der;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.X509.X509Certificate issued;
        X509Certificate2 client_cert;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out client_key, out _);
        csr = new Pkcs10 { Key = client_key };
        csr.SetSubject("CN=poodle", out _);
        crypto.EncodeCsr(csr, out csr_der, out _);
        parsed = new Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed.GetPublicKey(), "CN=poodle");
        client_cert = new X509Certificate2(issued.GetEncoded());
        return ca.BuildSuccessCertRep(issued, client_cert, "tx", new byte[16]);
    }

    private static byte[] StripCertificates(byte[] cert_rep) {
        CmsSignedData signed;
        IStore<Org.BouncyCastle.X509.X509Certificate> empty;

        signed = new CmsSignedData(cert_rep);
        empty = CollectionUtilities.CreateStore(new List<Org.BouncyCastle.X509.X509Certificate>());
        return CmsSignedData.ReplaceCertificatesAndCrls(signed, empty, null).GetEncoded();
    }

    [Fact]
    public void Decode_reports_the_claimed_signer_and_verifies_a_normal_certrep() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        PkiMessage msg;
        string error;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);

        Assert.True(crypto.DecodePkiMessage(cert_rep, client_key, CodecOptions.LenientParsing, null, out msg, out error), error);
        Assert.True(msg.SignatureValid);
        Assert.False(string.IsNullOrEmpty(msg.SignerClaimedIdentity));
    }

    [Fact]
    public void Verification_falls_back_to_the_GetCACert_bundle_when_the_signer_cert_is_absent() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        byte[] stripped;
        PkiMessage without;
        PkiMessage with;
        string error;
        string notes;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);
        stripped = StripCertificates(cert_rep);

        // No certs embedded and no known certs -> can't verify (the original false-negative finding).
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, null, out without, out error), error);
        Assert.False(without.SignatureValid);

        // Hand it the GetCACert bundle -> it finds the real signer and verifies.
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, new[] { ca.CertificateBcl }, out with, out error), error);
        Assert.True(with.SignatureValid);
        Assert.Equal(without.SignerClaimedIdentity, with.SignerClaimedIdentity);

        notes = string.Join(" ", with.ConformanceNotes.ConvertAll(n => n.What));
        Assert.Contains("GetCACert", notes);
    }

    [Fact]
    public void Unverifiable_signature_note_names_the_claimed_signer_and_what_was_tried() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        byte[] stripped;
        PkiMessage msg;
        string error;
        string notes;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);
        stripped = StripCertificates(cert_rep);

        // Stripped of certs, with an unrelated cert as the only candidate -> nothing verifies.
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, null, out msg, out error), error);
        Assert.False(msg.SignatureValid);

        notes = string.Join(" ", msg.ConformanceNotes.ConvertAll(n => n.What));
        Assert.Contains("claimed signer", notes);
        Assert.Contains(msg.SignerClaimedIdentity!, notes);
    }
}
