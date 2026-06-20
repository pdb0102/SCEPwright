namespace ScepTestClient.Crypto.BouncyCastle;

internal static class ScepAttributes {
    public const string MessageType = "2.16.840.1.113733.1.9.2";
    public const string PkiStatus = "2.16.840.1.113733.1.9.3";
    public const string FailInfo = "2.16.840.1.113733.1.9.4";
    public const string SenderNonce = "2.16.840.1.113733.1.9.5";
    public const string RecipientNonce = "2.16.840.1.113733.1.9.6";
    public const string TransId = "2.16.840.1.113733.1.9.7";

    public static string NumberFor(ScepTestClient.CryptoApi.MessageType type) {
        switch (type) {
            case ScepTestClient.CryptoApi.MessageType.CertRep: return "3";
            case ScepTestClient.CryptoApi.MessageType.RenewalReq: return "17";
            case ScepTestClient.CryptoApi.MessageType.PkcsReq: return "19";
            case ScepTestClient.CryptoApi.MessageType.CertPoll: return "20";
            case ScepTestClient.CryptoApi.MessageType.GetCert: return "21";
            case ScepTestClient.CryptoApi.MessageType.GetCrl: return "22";
            default: return ((int)type).ToString();
        }
    }
}
