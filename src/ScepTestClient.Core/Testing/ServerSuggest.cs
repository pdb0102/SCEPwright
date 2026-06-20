using System.Collections.Generic;
using ScepTestClient.Core.Protocol;

namespace ScepTestClient.Core.Testing;

public static class ServerSuggest {
    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps) {
        List<string> lines;
        List<string> digests;
        List<string> ciphers;

        lines = new List<string>();
        digests = new List<string>();
        ciphers = new List<string>();

        if (caps.Sha256) { digests.Add("SHA-256"); }
        if (caps.Sha512) { digests.Add("SHA-512"); }
        if (caps.Sha1) { digests.Add("SHA-1"); }
        if (digests.Count == 0) { digests.Add("SHA-256"); }

        if (caps.Aes) { ciphers.Add("AES-128-CBC"); }
        if (caps.Des3) { ciphers.Add("DES-EDE3-CBC"); }
        if (ciphers.Count == 0) { ciphers.Add("AES-128-CBC"); }

        foreach (string digest in digests) {
            foreach (string cipher in ciphers) {
                lines.Add($"sceptest enroll {server_id} --subject \"CN=test\" --key-spec rsa:2048 --digest {digest} --cipher {cipher}");
            }
        }
        return lines;
    }
}
