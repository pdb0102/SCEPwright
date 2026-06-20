using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class RenewRequest {
    public required string Subject { get; init; }
    public required X509Certificate2 ExistingCertificate { get; init; }
    public required IScepKey ExistingKey { get; init; }
    public RenewalVariant Variant { get; init; } = RenewalVariant.Proper;
    public string? ChallengePassword { get; init; }
    public string KeySpecText { get; init; } = "rsa:2048";
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public List<string> Ekus { get; } = new();
    public string? Sid { get; init; }
    public X509Certificate2? CaCertificate { get; set; }
}
