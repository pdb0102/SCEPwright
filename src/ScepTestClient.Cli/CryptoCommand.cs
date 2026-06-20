using System.Collections.Generic;
using System.IO;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Cli;

internal static class CryptoCommand {
    public static int Run(string[] args, string data_root, TextWriter output) {
        string verb;
        string? provider_path;
        IScepCrypto crypto;
        string error;

        if (args.Length < 2) {
            output.WriteLine("usage: crypto <info|list>");
            return 2;
        }
        verb = args[1];
        provider_path = CommandRouter.ResolveProviderPath(args, data_root);

        if (ScepCrypto.Load(provider_path, out crypto, out error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {error}");
            return 1;
        }

        switch (verb) {
            case "list":
                return List(crypto, output);

            case "info":
                return Info(crypto, provider_path, output);

            default:
                output.WriteLine("usage: crypto <info|list>");
                return 2;
        }
    }

    private static int List(IScepCrypto crypto, TextWriter output) {
        PrintGroup(output, "Digests", crypto.Capabilities.Digests);
        PrintGroup(output, "Signatures", crypto.Capabilities.Signatures);
        PrintGroup(output, "ContentEncryption", crypto.Capabilities.ContentEncryption);
        PrintGroup(output, "KeyTransport", crypto.Capabilities.KeyTransport);
        PrintGroup(output, "KEM", crypto.Capabilities.Kem);
        PrintGroup(output, "AsymmetricKeys", crypto.Capabilities.AsymmetricKeys);
        return 0;
    }

    private static int Info(IScepCrypto crypto, string? provider_path, TextWriter output) {
        output.WriteLine(string.IsNullOrWhiteSpace(provider_path)
            ? "Provider: built-in (BouncyCastle)"
            : $"Provider: {provider_path}");
        output.WriteLine($"Tier A: {(crypto.Capabilities.PqTiers.TierA ? "yes" : "no")}");
        output.WriteLine($"Tier B: {(crypto.Capabilities.PqTiers.TierB ? "yes" : "no")}");
        output.WriteLine($"Tier C: {(crypto.Capabilities.PqTiers.TierC ? "yes" : "no")}  (ML-KEM CMS envelope — provider seam; BouncyCastle 2.5.0 has no CMS KEM recipient)");
        return 0;
    }

    private static void PrintGroup(TextWriter output, string title, IReadOnlyCollection<string> oids) {
        List<string> names;

        names = new List<string>();
        foreach (string oid in oids) {
            names.Add(Algorithms.NameFor(oid) ?? oid);
        }
        output.WriteLine($"{title}: {string.Join(", ", names)}");
    }
}
