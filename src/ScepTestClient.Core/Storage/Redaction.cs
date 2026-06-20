using System;
using System.Security.Cryptography;
using System.Text;

namespace ScepTestClient.Core.Storage;

public static class Redaction {
    public static string Hash(string sensitive) {
        byte[] digest;

        digest = SHA256.HashData(Encoding.UTF8.GetBytes(sensitive ?? string.Empty));
        return "sha256:" + Convert.ToHexString(digest).ToLowerInvariant();
    }
}
