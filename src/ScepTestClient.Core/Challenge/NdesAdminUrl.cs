namespace ScepTestClient.Core.Challenge;

public static class NdesAdminUrl {
    public static string Derive(string scep_url, string? explicit_admin_url = null) {
        System.Uri uri;
        string path;

        if (!string.IsNullOrEmpty(explicit_admin_url)) { return explicit_admin_url!; }

        uri = new System.Uri(scep_url);
        path = uri.AbsolutePath;
        // Replace the 'mscep' segment with 'mscep_admin' and drop a trailing pkiclient.exe.
        path = path.Replace("/mscep/", "/mscep_admin/", System.StringComparison.OrdinalIgnoreCase);
        if (path.EndsWith("/mscep", System.StringComparison.OrdinalIgnoreCase)) {
            path = path.Substring(0, path.Length - "/mscep".Length) + "/mscep_admin/";
        }
        if (path.EndsWith("pkiclient.exe", System.StringComparison.OrdinalIgnoreCase)) {
            path = path.Substring(0, path.Length - "pkiclient.exe".Length);
        }
        return new System.UriBuilder(uri) { Path = path, Query = string.Empty }.Uri.ToString();
    }
}
