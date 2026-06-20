using System.IO;
using System.Text.Json;

namespace ScepTestClient.Core.Storage;

public sealed class ClientConfig {
    public string? CryptoProviderPath { get; set; }
    public string KeySpec { get; set; } = "rsa:2048";
    public int TimeoutSeconds { get; set; } = 30;
    public int MinRsaKeyBits { get; set; } = 2048;

    public static ClientConfig Load(string root) {
        string config_path;

        config_path = Path.Combine(root, "config.json");
        if (!File.Exists(config_path)) {
            return new ClientConfig();
        }

        try {
            ClientConfig? loaded;

            loaded = JsonSerializer.Deserialize<ClientConfig>(File.ReadAllText(config_path));
            return loaded ?? new ClientConfig();
        } catch {
            return new ClientConfig();
        }
    }

    public void Save(string root) {
        string config_path;

        config_path = Path.Combine(root, "config.json");
        Directory.CreateDirectory(root);
        File.WriteAllText(config_path, JsonSerializer.Serialize(this));
    }
}
