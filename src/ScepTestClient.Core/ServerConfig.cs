using System;

namespace ScepTestClient.Core;

public sealed class ServerConfig {
    public required string Id { get; init; }
    public required Uri Url { get; init; }
    public string? CaIdentifier { get; init; }
    public bool PreferPost { get; init; } = true;
}
