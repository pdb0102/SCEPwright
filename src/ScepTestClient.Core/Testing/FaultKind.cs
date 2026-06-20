namespace ScepTestClient.Core.Testing;

public enum FaultKind {
    ForbiddenAlgorithm,   // MD5 digest
    CorruptedSignature,
    SkewedSigningTime,
    WrongChallenge,
    UnknownCertId,        // GetCert unknown serial
    MalformedRequest,     // corrupt inner CSR
    RenewalNotAdvertised, // RenewalReq when Renewal cap absent
}
