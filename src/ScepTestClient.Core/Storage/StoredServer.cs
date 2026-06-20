namespace ScepTestClient.Core.Storage;

public sealed class StoredServer {
    public required string Id { get; set; }
    public required string Url { get; set; }
    public string? Name { get; set; }
    public string? CaIdentifier { get; set; }
    public bool PreferPost { get; set; } = true;
}
