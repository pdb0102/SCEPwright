using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

public sealed class Pkcs10 {
    public string Subject { get; private set; } = string.Empty;
    public IScepKey? Key { get; set; }
    public string? ChallengePassword { get; set; }
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public string? Sid { get; set; }
    public List<string> Ekus { get; } = new();
    public string? TemplateName { get; set; }
    public List<(string Oid, byte[] Value, bool Critical)> Extensions { get; } = new();

    public bool SetSubject(string subject, out string error) {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(subject)) {
            error = "subject DN must be non-empty";
            return false;
        }
        Subject = subject;
        return true;
    }

    public bool Encode(IScepCrypto crypto, out byte[] der, out string error) =>
        crypto.EncodeCsr(this, out der, out error);
}
