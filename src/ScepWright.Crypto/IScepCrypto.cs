using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepWright.Crypto;

/// <summary>
/// Cryptographic provider contract for the SCEP suite. All operations are pure (no exceptions for
/// control flow): each returns <c>true</c> on success with the result in an <c>out</c> value, or
/// <c>false</c> with a human-readable message in <c>out error</c>. Crypto must only be reached
/// through this interface; concrete implementations live in <c>ScepWright.Crypto.*</c>.
/// </summary>
public interface IScepCrypto {
    /// <summary>Gets the set of algorithms and features this provider supports.</summary>
    CryptoCapabilities Capabilities { get; }

    /// <summary>Generates a key pair for the given specification.</summary>
    bool GenerateKey(KeySpec spec, out IScepKey key, out string error);

    /// <summary>Encodes a PKCS#10 certificate-signing request to DER.</summary>
    bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error);

    /// <summary>Encodes a SCEP PKI message to DER, optionally injecting the given fault directives for negative testing.</summary>
    bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error);

    /// <summary>
    /// Decodes a SCEP PKI message from DER, decrypting with the recipient key and applying the given codec
    /// options. <paramref name="known_certs"/> (e.g. the GetCACert bundle) are added to the pool of
    /// certificates the response signature is verified against, so a valid signature whose signer cert was
    /// not embedded in the message can still be confirmed and diagnosed.
    /// </summary>
    bool DecodePkiMessage(byte[] der, IScepKey recipient_key, CodecOptions options, IReadOnlyList<X509Certificate2>? known_certs, out PkiMessage message, out string error);

    /// <summary>Parses a CA certificate bundle (degenerate PKCS#7 or raw cert) from DER.</summary>
    bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error);

    /// <summary>Exports a private key as unencrypted PKCS#8 DER.</summary>
    bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error);

    /// <summary>Imports a private key from unencrypted PKCS#8 DER.</summary>
    bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error);

    /// <summary>Exports a private key as encrypted PKCS#8 DER (PBES2/PBKDF2-HMAC-SHA256/AES-256) under the given passphrase.</summary>
    bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error);

    /// <summary>Imports a private key from encrypted PKCS#8 DER using the given passphrase.</summary>
    bool ImportPrivateKeyPkcs8Encrypted(byte[] der, string passphrase, out IScepKey key, out string error);

    /// <summary>
    /// Bundles a leaf certificate, its private key, and any chain certs into a password-protected
    /// PKCS#12 (.p12/.pfx) — the deployable artifact. <paramref name="legacy"/>=false emits modern
    /// PBES2/AES-256 bags (read natively by OpenSSL 3); <paramref name="legacy"/>=true emits the
    /// classic SHA-1/RC2/3DES bags for old importers.
    /// </summary>
    bool ExportPkcs12(IScepKey key, X509Certificate2 leaf, IReadOnlyList<X509Certificate2> chain, string password, bool legacy, out byte[] der, out string error);
}
