using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

public sealed class CryptoCapabilities {
    public IReadOnlyCollection<string> Digests { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> Signatures { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> ContentEncryption { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> KeyTransport { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> Kem { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> AsymmetricKeys { get; init; } = System.Array.Empty<string>();
}
