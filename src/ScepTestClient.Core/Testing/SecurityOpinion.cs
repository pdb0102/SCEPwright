namespace ScepTestClient.Core.Testing;

public enum AlgorithmPosture { MustNot, LegacyWeak, Modern, CuttingEdge, Unknown }

public static class SecurityOpinion {
    public static AlgorithmPosture ClassifyDigest(string name) {
        switch ((name ?? string.Empty).ToUpperInvariant()) {
            case "MD5": return AlgorithmPosture.MustNot;
            case "SHA-1": return AlgorithmPosture.LegacyWeak;
            case "SHA-256":
            case "SHA-512": return AlgorithmPosture.Modern;
            default: return AlgorithmPosture.Unknown;
        }
    }

    public static AlgorithmPosture ClassifyCipher(string name) {
        switch ((name ?? string.Empty).ToUpperInvariant()) {
            case "DES":
            case "DES-CBC": return AlgorithmPosture.MustNot;
            case "DES-EDE3-CBC":
            case "DES3":
            case "3DES": return AlgorithmPosture.LegacyWeak;
            case "AES-128-CBC":
            case "AES-256-CBC":
            case "AES": return AlgorithmPosture.Modern;
            default: return AlgorithmPosture.Unknown;
        }
    }

    public static AlgorithmPosture ClassifyRsa(int bits, OpinionThresholds thresholds) {
        if (bits < 1024) { return AlgorithmPosture.MustNot; }
        if (bits < thresholds.MinRsaKeyBits) { return AlgorithmPosture.LegacyWeak; }
        return AlgorithmPosture.Modern;
    }
}
