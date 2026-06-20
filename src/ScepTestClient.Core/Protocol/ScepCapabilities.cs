using System;
using System.Collections.Generic;

namespace ScepTestClient.Core.Protocol;

public sealed class ScepCapabilities {
    public bool Aes { get; private set; }
    public bool Des3 { get; private set; }
    public bool GetNextCaCert { get; private set; }
    public bool PostPkiOperation { get; private set; }
    public bool Renewal { get; private set; }
    public bool Sha1 { get; private set; }
    public bool Sha256 { get; private set; }
    public bool Sha512 { get; private set; }
    public bool ScepStandard { get; private set; }
    public List<string> Unknown { get; } = new();
    public string[] RawKeywords { get; private set; } = Array.Empty<string>();

    public static ScepCapabilities Parse(string text) {
        ScepCapabilities caps;
        List<string> raw;

        caps = new ScepCapabilities();
        raw = new List<string>();

        foreach (string line in (text ?? string.Empty).Split('\n')) {
            string kw;

            kw = line.Trim();
            if (kw.Length == 0) continue;
            raw.Add(kw);
            switch (kw.ToUpperInvariant()) {
                case "AES": caps.Aes = true; break;
                case "DES3": caps.Des3 = true; break;
                case "GETNEXTCACERT": caps.GetNextCaCert = true; break;
                case "POSTPKIOPERATION": caps.PostPkiOperation = true; break;
                case "RENEWAL": caps.Renewal = true; break;
                case "SHA-1": caps.Sha1 = true; break;
                case "SHA-256": caps.Sha256 = true; break;
                case "SHA-512": caps.Sha512 = true; break;
                case "SCEPSTANDARD": caps.ScepStandard = true; break;
                default: caps.Unknown.Add(kw); break;
            }
        }
        caps.RawKeywords = raw.ToArray();
        return caps;
    }
}
