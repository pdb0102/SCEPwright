using System;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class EnrollOutcome {
    public ScepClientResult Status { get; init; }
    public PkiStatus PkiStatus { get; init; }
    public FailInfo FailInfo { get; init; } = FailInfo.None;
    public X509Certificate2? Certificate { get; init; }
    public IScepKey? SubjectKey { get; init; }
    public string TransactionId { get; init; } = string.Empty;
    public TimeSpan Elapsed { get; init; }
}
