using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepTestClient.CryptoApi;

public sealed class PkiMessage {
    public MessageType MessageType { get; set; }
    public X509Certificate2? RecipientCaCert { get; set; }
    public X509Certificate2? SignerCert { get; set; }
    public IScepKey? SignerKey { get; set; }
    public Pkcs10? InnerCsr { get; set; }
    public string DigestAlgorithmOid { get; set; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionAlgorithmOid { get; set; } = Algorithms.OidFor("AES-128-CBC")!;
    public string? TransactionId { get; set; }

    public PkiStatus PkiStatus { get; set; }
    public FailInfo FailInfo { get; set; } = FailInfo.None;
    public string? FailInfoText { get; set; }
    public byte[]? SenderNonce { get; set; }
    public byte[]? RecipientNonce { get; set; }
    public bool SignatureValid { get; set; }
    public byte[]? DecryptedContent { get; set; }
    public IReadOnlyList<X509Certificate2> IssuedCerts { get; set; } = System.Array.Empty<X509Certificate2>();
    public List<ConformanceNote> ConformanceNotes { get; } = new();

    public bool Encode(IScepCrypto crypto, out byte[] der, out string error) =>
        crypto.EncodePkiMessage(this, faults: null, out der, out error);

    public bool Encode(IScepCrypto crypto, FaultDirectives? faults, out byte[] der, out string error) =>
        crypto.EncodePkiMessage(this, faults, out der, out error);

    public static bool Decode(IScepCrypto crypto, byte[] der, IScepKey key, CodecOptions options, out PkiMessage message, out string error) =>
        crypto.DecodePkiMessage(der, key, options, out message, out error);
}
