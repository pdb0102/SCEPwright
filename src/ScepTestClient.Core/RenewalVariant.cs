namespace ScepTestClient.Core;

public enum RenewalVariant {
    Proper,                 // RenewalReq(17), signed by existing cert+key, new subject key
    ReenrollSameSubject,    // PKCSReq(19), self-signed new key + challenge, same Subject DN
    RenewalShapedPkcsReq,   // PKCSReq(19), signed by existing cert+key, new subject key
    SameKey,                // RenewalReq(17), signed by existing cert+key, reuses existing key
    Expired,                // RenewalReq(17), signed by an expired existing cert
}
