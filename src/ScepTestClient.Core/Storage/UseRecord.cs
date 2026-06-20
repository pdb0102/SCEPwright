namespace ScepTestClient.Core.Storage;

public sealed class UseRecord {
    public string Operation { get; set; } = string.Empty;
    public string PkiStatus { get; set; } = string.Empty;
    public long TimingMs { get; set; }
    public string? CertId { get; set; }
    public string? FailInfo { get; set; }
    public string? TransactionId { get; set; }
}
