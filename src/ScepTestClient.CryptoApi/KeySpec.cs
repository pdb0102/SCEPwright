namespace ScepTestClient.CryptoApi;

public sealed class KeySpec {
    public string Algorithm { get; }
    public int Size { get; }
    public string Raw { get; }

    private KeySpec(string algorithm, int size, string raw) {
        Algorithm = algorithm;
        Size = size;
        Raw = raw;
    }

    public static bool Parse(string text, out KeySpec spec, out string error) {
        string[] parts;
        int bits;

        spec = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text)) {
            error = "key spec is empty";
            return false;
        }

        parts = text.Split(':');
        if (parts.Length != 2 || !parts[0].Equals("rsa", System.StringComparison.OrdinalIgnoreCase)) {
            error = $"unsupported key spec '{text}' (expected 'rsa:<bits>')";
            return false;
        }

        if (!int.TryParse(parts[1], out bits) || bits < 1024) {
            error = $"invalid RSA size in '{text}'";
            return false;
        }

        spec = new KeySpec("RSA", bits, text);
        return true;
    }
}
