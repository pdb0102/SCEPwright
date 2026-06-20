namespace ScepTestClient.CryptoApi;

// The only place deliberate faults live. Attached to a request via ScepRequestBuilder.AllowFaults(...)
// and applied ONLY inside the provider's `if (faults != null)` encode branch. Deleting this type,
// the builder method, and that branch makes the library production-pure.
public sealed class FaultDirectives {
    // Sign the CMS with a throwaway key so the signature fails to verify -> badMessageCheck.
    public bool CorruptSignature { get; set; }

    // Add a CMS signingTime authenticated attribute offset from now (e.g. +2h) -> badTime.
    public System.TimeSpan? SigningTimeSkew { get; set; }

    // Garble the inner payload before enveloping so no PKCS#10 can be parsed -> badRequest.
    public bool CorruptInnerContent { get; set; }
}
