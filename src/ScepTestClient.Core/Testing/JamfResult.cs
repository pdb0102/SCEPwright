using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Testing;

public sealed record JamfResult(
    bool TimedOut,
    PkiStatus FinalStatus,
    System.TimeSpan Elapsed,
    int PollCount,
    X509Certificate2? Certificate);
