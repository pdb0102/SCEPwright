using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

public sealed record AlgorithmEntry(string Name, string Oid, AlgorithmKind Kind);

public static class Algorithms {
    private static readonly AlgorithmEntry[] Entries =
    {
        new("SHA-1",       "1.3.14.3.2.26",                 AlgorithmKind.Digest),
        new("SHA-256",     "2.16.840.1.101.3.4.2.1",        AlgorithmKind.Digest),
        new("SHA-512",     "2.16.840.1.101.3.4.2.3",        AlgorithmKind.Digest),
        new("MD5",         "1.2.840.113549.2.5",            AlgorithmKind.Digest),
        new("AES-128-CBC", "2.16.840.1.101.3.4.1.2",        AlgorithmKind.ContentEncryption),
        new("AES-256-CBC", "2.16.840.1.101.3.4.1.42",       AlgorithmKind.ContentEncryption),
        new("DES-EDE3-CBC","1.2.840.113549.3.7",            AlgorithmKind.ContentEncryption),
        new("RSA",         "1.2.840.113549.1.1.1",          AlgorithmKind.AsymmetricKey),
        new("ML-DSA-44",   "2.16.840.1.101.3.4.3.17",       AlgorithmKind.Signature),
        new("ML-DSA-65",   "2.16.840.1.101.3.4.3.18",       AlgorithmKind.Signature),
        new("ML-DSA-87",   "2.16.840.1.101.3.4.3.19",       AlgorithmKind.Signature),
        new("SLH-DSA-128s","2.16.840.1.101.3.4.3.20",       AlgorithmKind.Signature),
        new("SLH-DSA-128f","2.16.840.1.101.3.4.3.21",       AlgorithmKind.Signature),
        new("SLH-DSA-192s","2.16.840.1.101.3.4.3.22",       AlgorithmKind.Signature),
        new("SLH-DSA-192f","2.16.840.1.101.3.4.3.23",       AlgorithmKind.Signature),
        new("SLH-DSA-256s","2.16.840.1.101.3.4.3.24",       AlgorithmKind.Signature),
        new("SLH-DSA-256f","2.16.840.1.101.3.4.3.25",       AlgorithmKind.Signature),
        new("ML-KEM-512",  "2.16.840.1.101.3.4.4.1",        AlgorithmKind.Kem),
        new("ML-KEM-768",  "2.16.840.1.101.3.4.4.2",        AlgorithmKind.Kem),
        new("ML-KEM-1024", "2.16.840.1.101.3.4.4.3",        AlgorithmKind.Kem),
    };

    private static readonly Dictionary<string, AlgorithmEntry> ByName = BuildIndex(static e => e.Name);
    private static readonly Dictionary<string, AlgorithmEntry> ByOid = BuildIndex(static e => e.Oid);

    private static Dictionary<string, AlgorithmEntry> BuildIndex(System.Func<AlgorithmEntry, string> key) {
        Dictionary<string, AlgorithmEntry> map;

        map = new Dictionary<string, AlgorithmEntry>(System.StringComparer.OrdinalIgnoreCase);
        foreach (AlgorithmEntry entry in Entries) {
            map[key(entry)] = entry;
        }
        return map;
    }

    public static string? OidFor(string name) => ByName.TryGetValue(name, out AlgorithmEntry? e) ? e.Oid : null;

    public static string? NameFor(string oid) => ByOid.TryGetValue(oid, out AlgorithmEntry? e) ? e.Name : null;

    public static AlgorithmKind? KindOf(string oid) => ByOid.TryGetValue(oid, out AlgorithmEntry? e) ? e.Kind : null;
}
