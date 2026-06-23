using System.IO;
using System.Text.Json;
using ScepWright.Crypto;

namespace ScepWright.Core.Storage;

/// <summary>
/// On-disk store of PENDING enrollments awaiting CA approval, keyed by server and SCEP transaction id.
/// Holds the original subject private key and request metadata so a later <c>poll</c> can sign the
/// CertPoll with that key (RFC 8894 §3.3.2) and persist the issued certificate paired with it — without
/// this, the polled certificate has no matching key on disk and never appears in <c>certs list</c>.
/// </summary>
public sealed class PendingStore {
    private readonly string _root;

    /// <summary>Creates a store rooted at the given data directory.</summary>
    public PendingStore(string root) {
        _root = root;
    }

    private string Dir(string server_id, string transaction_id) {
        return Path.Combine(_root, "servers", server_id, "pending", transaction_id);
    }

    /// <summary>
    /// Persists the subject key and request metadata for a pending enrollment. The key is written
    /// encrypted when <paramref name="passphrase"/> is supplied, otherwise as plaintext PKCS#8.
    /// </summary>
    public void Save(string server_id, string transaction_id, IScepKey key, IScepCrypto crypto,
                     string? key_spec_text, string? passphrase = null) {
        string dir;
        byte[] key_der;
        string key_error;
        PendingRecord record;

        dir = Dir(server_id, transaction_id);
        Directory.CreateDirectory(dir);

        if (!string.IsNullOrEmpty(passphrase)) {
            if (crypto.ExportPrivateKeyPkcs8Encrypted(key, passphrase!, out key_der, out key_error)) {
                File.WriteAllBytes(Path.Combine(dir, "key.pkcs8.enc"), key_der);
            }
        } else if (crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) {
            File.WriteAllBytes(Path.Combine(dir, "key.pkcs8"), key_der);
        }

        record = new PendingRecord {
            TransactionId = transaction_id,
            KeySpec = key_spec_text,
        };
        File.WriteAllText(Path.Combine(dir, "request.json"), JsonSerializer.Serialize(record));
    }

    /// <summary>
    /// Loads the subject key and metadata for a pending enrollment. A <paramref name="passphrase"/> is
    /// required if the key was stored encrypted.
    /// </summary>
    public bool TryLoad(string server_id, string transaction_id, IScepCrypto crypto,
                        out IScepKey key, out PendingRecord record, out string error, string? passphrase = null) {
        string dir;
        string plain_path;
        string enc_path;

        key = null!;
        record = null!;
        error = string.Empty;

        dir = Dir(server_id, transaction_id);
        if (!Directory.Exists(dir)) {
            error = $"no pending enrollment for transaction '{transaction_id}' under server '{server_id}'";
            return false;
        }

        plain_path = Path.Combine(dir, "key.pkcs8");
        enc_path = Path.Combine(dir, "key.pkcs8.enc");
        if (File.Exists(enc_path)) {
            if (string.IsNullOrEmpty(passphrase)) {
                error = $"pending enrollment '{transaction_id}' has an encrypted key; a passphrase is required";
                return false;
            }
            if (!crypto.ImportPrivateKeyPkcs8Encrypted(File.ReadAllBytes(enc_path), passphrase!, out key, out error)) {
                return false;
            }
        } else if (File.Exists(plain_path)) {
            if (!crypto.ImportPrivateKeyPkcs8(File.ReadAllBytes(plain_path), out key, out error)) {
                return false;
            }
        } else {
            error = $"no stored key for pending enrollment '{transaction_id}'";
            return false;
        }

        record = JsonSerializer.Deserialize<PendingRecord>(File.ReadAllText(Path.Combine(dir, "request.json")))!;
        return true;
    }

    /// <summary>Removes a pending enrollment once its certificate has been issued and persisted.</summary>
    public void Delete(string server_id, string transaction_id) {
        string dir;

        dir = Dir(server_id, transaction_id);
        if (Directory.Exists(dir)) {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Persisted metadata about a pending enrollment.</summary>
    public sealed class PendingRecord {
        /// <summary>Gets or sets the SCEP transaction id of the pending request.</summary>
        public string TransactionId { get; set; } = string.Empty;
        /// <summary>Gets or sets the key spec the request was enrolled with.</summary>
        public string? KeySpec { get; set; }
    }
}
