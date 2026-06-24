using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepWright.Crypto;

/// <summary>
/// A SCEP PKI message (pkiMessage). The same object models both directions: request-input
/// properties are populated by the caller before <see cref="Encode(IScepCrypto, out byte[], out string)"/>,
/// while decode-output properties are populated by <see cref="Decode"/> from a received message.
/// </summary>
public sealed class PkiMessage {
    /// <summary>Gets or sets the SCEP message type.</summary>
    public MessageType MessageType { get; set; }
    /// <summary>Gets or sets the CA/RA certificate the request is enveloped to (request input).</summary>
    public X509Certificate2? RecipientCaCert { get; set; }
    /// <summary>Gets or sets the certificate used to sign the outer message (request input).</summary>
    public X509Certificate2? SignerCert { get; set; }
    /// <summary>Gets or sets the private key matching <see cref="SignerCert"/> (request input).</summary>
    public IScepKey? SignerKey { get; set; }
    /// <summary>Gets or sets the inner PKCS#10 CSR carried by a PKCSReq (request input).</summary>
    public Pkcs10? InnerCsr { get; set; }
    /// <summary>Gets or sets the OID of the signature digest algorithm. Defaults to SHA-256.</summary>
    public string DigestAlgorithmOid { get; set; } = Algorithms.OidFor("SHA-256")!;
    /// <summary>Gets or sets the OID of the envelope content-encryption algorithm. Defaults to AES-128-CBC.</summary>
    public string ContentEncryptionAlgorithmOid { get; set; } = Algorithms.OidFor("AES-128-CBC")!;
    /// <summary>Gets or sets the SCEP transaction id.</summary>
    public string? TransactionId { get; set; }
    /// <summary>Gets or sets the issuer DN of the target cert's CA (GetCert / GetCrl request input).</summary>
    public string? IssuerName { get; set; }
    /// <summary>Gets or sets the target cert serial number in hex (X509Certificate2.SerialNumber form) for GetCert / GetCrl.</summary>
    public string? SerialNumber { get; set; }
    /// <summary>Gets or sets the subject DN being polled (CertPoll request input).</summary>
    public string? SubjectName { get; set; }

    /// <summary>Gets or sets the SCEP transaction status (decode output on a CertRep).</summary>
    public PkiStatus PkiStatus { get; set; }
    /// <summary>Gets or sets the failure reason when <see cref="PkiStatus"/> is FAILURE (decode output).</summary>
    public FailInfo FailInfo { get; set; } = FailInfo.None;
    /// <summary>Gets or sets free-text accompanying <see cref="FailInfo"/> (decode output).</summary>
    public string? FailInfoText { get; set; }
    /// <summary>Gets or sets the sender nonce.</summary>
    public byte[]? SenderNonce { get; set; }
    /// <summary>Gets or sets the recipient nonce.</summary>
    public byte[]? RecipientNonce { get; set; }
    /// <summary>Gets or sets whether the outer signature verified (decode output).</summary>
    public bool SignatureValid { get; set; }
    /// <summary>
    /// Gets or sets the signer identity the response *claimed* (the CMS SignerIdentifier — issuer+serial or
    /// subjectKeyIdentifier), so a diagnostic can compare who signed against which cert was checked (decode output).
    /// </summary>
    public string? SignerClaimedIdentity { get; set; }
    /// <summary>
    /// Gets or sets a description of the certificate whose public key actually verified the signature, and
    /// where it came from (the CertRep's own bag or the GetCACert bundle), or null if none verified (decode output).
    /// </summary>
    public string? SignerVerifiedWith { get; set; }
    /// <summary>Gets or sets the decrypted inner content (decode output).</summary>
    public byte[]? DecryptedContent { get; set; }
    /// <summary>Gets or sets the certificates returned in a successful CertRep (decode output).</summary>
    public IReadOnlyList<X509Certificate2> IssuedCerts { get; set; } = System.Array.Empty<X509Certificate2>();
    /// <summary>Gets or sets the CRLs returned in a GetCRL response (decode output).</summary>
    public IReadOnlyList<byte[]> IssuedCrls { get; set; } = System.Array.Empty<byte[]>();
    /// <summary>Gets conformance notes recorded while decoding (decode output).</summary>
    public List<ConformanceNote> ConformanceNotes { get; } = new();

    /// <summary>Encodes this message to DER with no fault injection.</summary>
    public bool Encode(IScepCrypto crypto, out byte[] der, out string error) =>
        Encode(crypto, faults: null, out der, out error);

    /// <summary>Encodes this message to DER, optionally injecting fault directives for negative testing.</summary>
    public bool Encode(IScepCrypto crypto, FaultDirectives? faults, out byte[] der, out string error) {
        der = System.Array.Empty<byte>();

        if (!CapabilityGuard.Check(this, crypto.Capabilities, out error)) {
            return false;
        }

        return crypto.EncodePkiMessage(this, faults, out der, out error);
    }

    /// <summary>
    /// Decodes a SCEP PKI message from DER, decrypting with the given recipient key. Pass
    /// <paramref name="known_certs"/> (e.g. the GetCACert bundle) so a response whose signer cert is not
    /// embedded can still have its signature verified and diagnosed.
    /// </summary>
    public static bool Decode(IScepCrypto crypto, byte[] der, IScepKey key, CodecOptions options, out PkiMessage message, out string error,
                              IReadOnlyList<X509Certificate2>? known_certs = null) =>
        crypto.DecodePkiMessage(der, key, options, known_certs, out message, out error);
}
