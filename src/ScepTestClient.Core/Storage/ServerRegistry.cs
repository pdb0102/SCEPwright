using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ScepTestClient.Core.Storage;

public sealed class ServerRegistry {
    private readonly string _servers_dir;

    public ServerRegistry(string root) {
        _servers_dir = Path.Combine(root, "servers");
        Directory.CreateDirectory(_servers_dir);
    }

    public void Add(StoredServer server) {
        string server_dir;
        string json;

        server_dir = Path.Combine(_servers_dir, server.Id);
        Directory.CreateDirectory(server_dir);
        json = JsonSerializer.Serialize(server);
        File.WriteAllText(Path.Combine(server_dir, "server.json"), json);
    }

    public IReadOnlyList<StoredServer> List() {
        List<StoredServer> result;
        string[] dirs;

        result = new List<StoredServer>();
        dirs = Directory.GetDirectories(_servers_dir);

        foreach (string dir in dirs) {
            string json_path;
            StoredServer? server;

            json_path = Path.Combine(dir, "server.json");
            if (!File.Exists(json_path)) {
                continue;
            }

            try {
                server = JsonSerializer.Deserialize<StoredServer>(File.ReadAllText(json_path));
                if (server != null) {
                    result.Add(server);
                }
            } catch {
                // skip corrupt entries
            }
        }

        return result.AsReadOnly();
    }

    public StoredServer? Get(string id) {
        string json_path;

        json_path = Path.Combine(_servers_dir, id, "server.json");
        if (!File.Exists(json_path)) {
            return null;
        }

        try {
            return JsonSerializer.Deserialize<StoredServer>(File.ReadAllText(json_path));
        } catch {
            return null;
        }
    }
}
