namespace ScepTestClient.CryptoApi;

[Flags]
public enum CodecOptions {
    Strict = 0,
    LenientParsing = 1,
    SkipSignatureVerification = 2,
    AllowLegacyAlgorithms = 4,
}
