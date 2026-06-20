namespace ScepTestClient.CryptoApi;

public sealed class KeySpec {
    private static readonly string[] MlDsaSets = { "44", "65", "87" };
    private static readonly string[] SlhDsaSets = { "128s", "192s", "256s" };
    private static readonly string[] MlKemSets = { "512", "768", "1024" };

    public string Algorithm { get; }
    public int Size { get; }
    public string Parameter { get; }
    public string Raw { get; }

    private KeySpec(string algorithm, int size, string parameter, string raw) {
        Algorithm = algorithm;
        Size = size;
        Parameter = parameter;
        Raw = raw;
    }

    public static bool Parse(string text, out KeySpec spec, out string error) {
        string[] parts;
        string algo;
        string param;
        int bits;

        spec = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text)) {
            error = "key spec is empty";
            return false;
        }

        parts = text.Split(':');
        if (parts.Length != 2) {
            error = $"unsupported key spec '{text}' (expected 'rsa:<bits>' / 'ml-dsa:<set>' / 'slh-dsa:<set>')";
            return false;
        }

        algo = parts[0].ToLowerInvariant();
        param = parts[1];

        if (algo == "rsa") {
            if (!int.TryParse(param, out bits) || bits < 1024) {
                error = $"invalid RSA size in '{text}'";
                return false;
            }
            spec = new KeySpec("RSA", bits, string.Empty, text);
            return true;
        }

        if (algo == "ml-dsa") {
            if (System.Array.IndexOf(MlDsaSets, param) < 0) {
                error = $"invalid ML-DSA parameter set '{param}' (expected 44/65/87)";
                return false;
            }
            spec = new KeySpec("ML-DSA", 0, param, text);
            return true;
        }

        if (algo == "slh-dsa") {
            if (System.Array.IndexOf(SlhDsaSets, param) < 0) {
                error = $"invalid SLH-DSA parameter set '{param}'";
                return false;
            }
            spec = new KeySpec("SLH-DSA", 0, param, text);
            return true;
        }

        if (algo == "ml-kem") {
            if (System.Array.IndexOf(MlKemSets, param) < 0) {
                error = $"invalid ML-KEM parameter set '{param}' (expected 512/768/1024)";
                return false;
            }
            spec = new KeySpec("ML-KEM", 0, param, text);
            return true;
        }

        error = $"unsupported key spec '{text}'";
        return false;
    }
}
