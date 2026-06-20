using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class EnrollRequest {
    public required string Subject { get; init; }
    public required IScepKey Key { get; init; }
    public IScepKey? AltKey { get; init; }
    public string? ChallengePassword { get; init; }
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public string? Sid { get; init; }
    public List<string> Ekus { get; } = new();
    public X509Certificate2? CaCertificate { get; set; }
}
