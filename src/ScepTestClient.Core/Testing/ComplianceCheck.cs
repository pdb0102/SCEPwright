using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

public sealed record ComplianceCheck(string Name, FaultKind Kind, FailInfo Expected, string RfcReference);
