using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

public sealed record CheckResult(
    string Name,
    CheckOutcome Outcome,
    FailInfo Expected,
    FailInfo Got,
    PkiStatus GotStatus,
    string Why,
    string RfcReference,
    System.TimeSpan Elapsed);
