using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Storage;

public sealed class CertStore {
    private readonly string _root;

    public CertStore(string root) {
        _root = root;
    }

    public string Save(string server_id, X509Certificate2 cert, EnrollRequest request, IScepCrypto crypto) {
        string cert_id;
        string cert_dir;
        string pem_path;
        string key_path;
        string meta_path;
        byte[] key_der;
        string key_error;
        CertMetadata metadata;

        cert_id = cert.Thumbprint.ToLowerInvariant();
        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        Directory.CreateDirectory(cert_dir);

        pem_path = Path.Combine(cert_dir, "cert.pem");
        File.WriteAllText(pem_path, cert.ExportCertificatePem());

        key_path = Path.Combine(cert_dir, "key.pkcs8");
        if (crypto.ExportPrivateKeyPkcs8(request.Key, out key_der, out key_error)) {
            File.WriteAllBytes(key_path, key_der);
        }

        metadata = new CertMetadata {
            Subject = cert.Subject,
            Serial = cert.SerialNumber,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            ChallengePasswordHash = request.ChallengePassword != null
                ? Redaction.Hash(request.ChallengePassword)
                : null,
        };

        meta_path = Path.Combine(cert_dir, "metadata.json");
        File.WriteAllText(meta_path, JsonSerializer.Serialize(metadata));

        return cert_id;
    }

    private sealed class CertMetadata {
        public string Subject { get; set; } = string.Empty;
        public string Serial { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Thumbprint { get; set; } = string.Empty;
        public string? ChallengePasswordHash { get; set; }
    }
}
