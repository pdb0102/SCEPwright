using System;
using System.IO;
using System.Text.Json;

namespace ScepTestClient.Core.Storage;

public static class DataRoot {
    private const string BreadcrumbFileName = ".sceptest.json";
    private const string DefaultDirName = ".sceptestclient";

    public static string Resolve(string? explicit_dir, string? home_override = null) {
        string home;
        string breadcrumb_path;
        string default_root;

        if (!string.IsNullOrEmpty(explicit_dir)) {
            return explicit_dir;
        }

        home = home_override ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        breadcrumb_path = Path.Combine(home, BreadcrumbFileName);
        default_root = Path.Combine(home, DefaultDirName);

        if (File.Exists(breadcrumb_path)) {
            try {
                string json;
                BreadcrumbData? data;

                json = File.ReadAllText(breadcrumb_path);
                data = JsonSerializer.Deserialize<BreadcrumbData>(json);
                if (data != null && !string.IsNullOrEmpty(data.Root)) {
                    return data.Root;
                }
            } catch {
                // fall through to default
            }
        }

        try {
            BreadcrumbData breadcrumb;
            string json;

            breadcrumb = new BreadcrumbData { Root = default_root };
            json = JsonSerializer.Serialize(breadcrumb);
            File.WriteAllText(breadcrumb_path, json);
        } catch {
            // best-effort; never throw if home unwritable
        }

        return default_root;
    }

    private sealed class BreadcrumbData {
        public string Root { get; set; } = string.Empty;
    }
}
