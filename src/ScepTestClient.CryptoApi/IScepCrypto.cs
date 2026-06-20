using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepTestClient.CryptoApi;

// PQ readiness check (validated 2026-06-19):
//  Tier A (PQ end-entity key): KeySpec gains "ml-dsa:65" etc.; GenerateKey returns an IScepKey
//      with a PQ AlgorithmOid; EncodeCsr emits a PQ SubjectPublicKeyInfo. No signature change.
//  Tier B (catalyst alt-key): add optional alt-key fields to Pkcs10 (new properties, ignored by
//      existing callers). No interface change.
//  Tier C (PQ transport / ML-KEM envelope): EncodePkiMessage already takes the recipient via
//      PkiMessage.RecipientCaCert; a PQ recipient triggers KEMRecipientInfo inside the provider.
//      No signature change.
public interface IScepCrypto {
    CryptoCapabilities Capabilities { get; }

    bool GenerateKey(KeySpec spec, out IScepKey key, out string error);

    bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error);

    bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error);

    bool DecodePkiMessage(byte[] der, IScepKey recipient_key, CodecOptions options, out PkiMessage message, out string error);

    bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error);

    bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error);
}
