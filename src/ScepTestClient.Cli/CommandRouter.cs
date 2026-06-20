using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using ScepTestClient.Core;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Cli;

public static class CommandRouter {
    public static int Run(string[] args, string data_root, TextWriter output) {
        try {
            return RunInternal(args, data_root, output);
        } catch (Exception ex) {
            output.WriteLine($"fatal: {ex.Message}");
            return 1;
        }
    }

    // -------------------------------------------------------------------------
    // Internal dispatch
    // -------------------------------------------------------------------------

    private static int RunInternal(string[] args, string data_root, TextWriter output) {
        string noun;

        if (args == null || args.Length == 0) {
            return WriteUsage(output);
        }

        noun = args[0];

        switch (noun) {
            case "servers":
                return RunServers(args, data_root, output);

            case "getcacaps":
                return RunGetCaCaps(args, data_root, output);

            case "get":
                return RunGet(args, data_root, output);

            case "getcacert":
                return RunGetCaCert(args, data_root, output);

            case "getnextcacert":
                return RunGetNextCaCert(args, data_root, output);

            case "enroll":
                return RunGet(args, data_root, output);   // enroll == get without lifecycle sugar; same options

            case "renew":
                return RunRenew(args, data_root, output);

            case "getcert":
                return RunGetCert(args, data_root, output);

            case "getcrl":
                return RunGetCrl(args, data_root, output);

            case "poll":
                return RunPoll(args, data_root, output);

            case "certs":
                return RunCerts(args, data_root, output);

            case "config":
                return RunConfig(args, data_root, output);

            case "--help":
            case "-h":
            case "help":
                return WriteUsage(output);

            default:
                return WriteUsage(output);
        }
    }

    // -------------------------------------------------------------------------
    // servers sub-commands
    // -------------------------------------------------------------------------

    private static int RunServers(string[] args, string data_root, TextWriter output) {
        string verb;

        if (args.Length < 2) {
            return WriteUsage(output);
        }

        verb = args[1];

        switch (verb) {
            case "add":
                return RunServersAdd(args, data_root, output);

            case "list":
                return RunServersList(data_root, output);

            case "show":
                return RunServersShow(args, data_root, output);

            default:
                return WriteUsage(output);
        }
    }

    private static int RunServersAdd(string[] args, string data_root, TextWriter output) {
        string url;
        string? name;
        string? ca_identifier;
        string? transport;
        string id;
        ServerRegistry registry;
        StoredServer server;

        if (args.Length < 3) {
            output.WriteLine("usage: servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get|post]");
            return 2;
        }

        url = args[2];
        name = Opt(args, "--name");
        ca_identifier = Opt(args, "--ca-identifier");
        transport = Opt(args, "--transport");

        id = DeriveId(url, name);

        server = new StoredServer {
            Id = id,
            Url = url,
            Name = name,
            CaIdentifier = ca_identifier,
            PreferPost = !string.Equals(transport, "get", StringComparison.OrdinalIgnoreCase),
        };

        registry = new ServerRegistry(data_root);
        registry.Add(server);
        output.WriteLine($"added server '{id}' -> {url}");
        return 0;
    }

    private static int RunServersList(string data_root, TextWriter output) {
        ServerRegistry registry;
        IReadOnlyList<StoredServer> servers;

        registry = new ServerRegistry(data_root);
        servers = registry.List();

        foreach (StoredServer s in servers) {
            output.WriteLine($"{s.Id}\t{s.Url}");
        }

        return 0;
    }

    private static int RunServersShow(string[] args, string data_root, TextWriter output) {
        string id;
        ServerRegistry registry;
        StoredServer? server;

        if (args.Length < 3) {
            output.WriteLine("usage: servers show <id>");
            return 2;
        }

        id = args[2];
        registry = new ServerRegistry(data_root);
        server = registry.Get(id);

        if (server is null) {
            output.WriteLine($"unknown server '{id}'");
            return 2;
        }

        output.WriteLine($"Id:           {server.Id}");
        output.WriteLine($"Url:          {server.Url}");
        output.WriteLine($"Name:         {server.Name ?? "(none)"}");
        output.WriteLine($"CaIdentifier: {server.CaIdentifier ?? "(none)"}");
        output.WriteLine($"PreferPost:   {server.PreferPost}");
        return 0;
    }

    // -------------------------------------------------------------------------
    // getcacaps
    // -------------------------------------------------------------------------

    private static int RunGetCaCaps(string[] args, string data_root, TextWriter output) {
        string server_id;
        ServerRegistry registry;
        StoredServer? stored;
        IScepCrypto crypto;
        string crypto_error;
        ScepClientResult load_result;
        ScepClient client;
        string client_error;
        ScepClientResult create_result;
        ScepResult<ScepCapabilities> caps_result;
        ServerConfig config;

        if (args.Length < 2) {
            output.WriteLine("usage: getcacaps <serverId>");
            return 2;
        }

        server_id = args[1];
        registry = new ServerRegistry(data_root);
        stored = registry.Get(server_id);

        if (stored is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return 2;
        }

        load_result = ScepCrypto.Load(null, out crypto, out crypto_error);
        if (load_result != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return 1;
        }

        config = new ServerConfig {
            Id = stored.Id,
            Url = new Uri(stored.Url),
            CaIdentifier = stored.CaIdentifier,
            PreferPost = stored.PreferPost,
        };

        create_result = ScepClient.Create(config, crypto, null, out client, out client_error);
        if (create_result != ScepClientResult.Ok) {
            output.WriteLine($"client create error: {client_error}");
            return 1;
        }

        caps_result = client.GetCaCaps();
        if (!caps_result.IsOk) {
            output.WriteLine($"getcacaps failed: {caps_result.Status} {caps_result.Error}");
            return 1;
        }

        output.WriteLine(string.Join(", ", caps_result.Value.RawKeywords));
        return 0;
    }

    // -------------------------------------------------------------------------
    // get (new certificate)
    // -------------------------------------------------------------------------

    private static int RunGet(string[] args, string data_root, TextWriter output) {
        string server_id;
        string? subject;
        string? challenge;
        string? key_spec_str;
        string? sid;
        int verbosity;
        bool encrypt_keys;
        string? key_pass;
        ServerRegistry registry;
        StoredServer? stored;
        IScepCrypto crypto;
        string crypto_error;
        ScepClientResult load_result;
        KeySpec spec;
        string key_spec_error;
        IScepKey key;
        string key_error;
        ScepClient client;
        string client_error;
        ScepClientResult create_result;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;
        ServerConfig config;
        ConsoleTrace tracer;

        if (args.Length < 2) {
            output.WriteLine("usage: get <serverId> --subject \"CN=x\" [--challenge <pw>] [--key-spec rsa:2048] [--sid <s>] [-v]");
            return 2;
        }

        server_id = args[1];
        subject = Opt(args, "--subject");
        challenge = Opt(args, "--challenge");
        key_spec_str = Opt(args, "--key-spec") ?? "rsa:2048";
        sid = Opt(args, "--sid");
        verbosity = CountFlag(args, "-v");
        encrypt_keys = HasFlag(args, "--encrypt-keys");
        key_pass = Opt(args, "--key-pass");

        if (string.IsNullOrWhiteSpace(subject)) {
            output.WriteLine("--subject is required");
            return 2;
        }

        registry = new ServerRegistry(data_root);
        stored = registry.Get(server_id);

        if (stored is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return 2;
        }

        load_result = ScepCrypto.Load(null, out crypto, out crypto_error);
        if (load_result != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return 1;
        }

        if (!KeySpec.Parse(key_spec_str, out spec, out key_spec_error)) {
            output.WriteLine($"invalid key spec: {key_spec_error}");
            return 2;
        }

        if (!crypto.GenerateKey(spec, out key, out key_error)) {
            output.WriteLine($"key generation failed: {key_error}");
            return 1;
        }

        config = new ServerConfig {
            Id = stored.Id,
            Url = new Uri(stored.Url),
            CaIdentifier = stored.CaIdentifier,
            PreferPost = stored.PreferPost,
        };

        create_result = ScepClient.Create(config, crypto, null, out client, out client_error);
        if (create_result != ScepClientResult.Ok) {
            output.WriteLine($"client create error: {client_error}");
            return 1;
        }

        tracer = new ConsoleTrace(verbosity);
        client.Trace += tracer.Handle;

        request = new EnrollRequest {
            Subject = subject,
            Key = key,
            ChallengePassword = challenge,
            Sid = sid,
        };

        outcome = client.GetNewCertificate(request, new CertStore(data_root), new UseRecordLog(data_root));

        if (outcome.IsOk && encrypt_keys && outcome.Value.Certificate is not null) {
            new CertStore(data_root).Save(stored.Id, outcome.Value.Certificate, key, crypto,
                challenge_password: challenge, renewed_from: null, transaction_id: outcome.Value.TransactionId, passphrase: key_pass ?? string.Empty);
        }

        if (outcome.IsOk) {
            string cert_subject;
            cert_subject = outcome.Value.Certificate?.Subject ?? "(no certificate)";
            output.WriteLine($"issued: {cert_subject} (stored under server '{stored.Id}')");
            return 0;
        }

        output.WriteLine($"FAILED: {outcome.Status} {outcome.Error}");
        return 1;
    }

    // -------------------------------------------------------------------------
    // Phase-2 operations: getcacert, getnextcacert, renew, getcert, getcrl, poll
    // -------------------------------------------------------------------------

    private static bool BuildClient(string server_id, string data_root, TextWriter output, out ScepClient client, out StoredServer stored) {
        ServerRegistry registry;
        StoredServer? found;
        IScepCrypto crypto;
        string crypto_error;
        ServerConfig config;
        string client_error;

        client = null!;
        stored = null!;

        registry = new ServerRegistry(data_root);
        found = registry.Get(server_id);
        if (found is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return false;
        }
        stored = found;

        if (ScepCrypto.Load(null, out crypto, out crypto_error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return false;
        }

        config = new ServerConfig {
            Id = stored.Id,
            Url = new Uri(stored.Url),
            CaIdentifier = stored.CaIdentifier,
            PreferPost = stored.PreferPost,
        };

        if (ScepClient.Create(config, crypto, null, out client, out client_error) != ScepClientResult.Ok) {
            output.WriteLine($"client create error: {client_error}");
            return false;
        }
        return true;
    }

    private static int RunGetCaCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> result;

        if (args.Length < 2) { output.WriteLine("usage: getcacert <serverId>"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCaCert();
        if (!result.IsOk) { output.WriteLine($"getcacert failed: {result.Status} {result.Error}"); return 1; }
        foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 c in result.Value) {
            output.WriteLine(c.Subject);
        }
        return 0;
    }

    private static int RunGetNextCaCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> result;

        if (args.Length < 2) { output.WriteLine("usage: getnextcacert <serverId>"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetNextCaCert();
        if (!result.IsOk) { output.WriteLine($"getnextcacert failed: {result.Status} {result.Error}"); return 1; }
        foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 c in result.Value) {
            output.WriteLine(c.Subject);
        }
        return 0;
    }

    private static int RunRenew(string[] args, string data_root, TextWriter output) {
        string cert_id;
        string? variant_text;
        string? passphrase;
        bool encrypt;
        CertStore store;
        string? server_id;
        ScepClient client;
        StoredServer stored;
        ScepResult<EnrollOutcome> result;
        RenewalVariant variant;

        if (args.Length < 2) { output.WriteLine("usage: renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--encrypt-keys] [--key-pass <pw>]"); return 2; }

        cert_id = args[1];
        variant_text = Opt(args, "--variant");
        encrypt = HasFlag(args, "--encrypt-keys");
        passphrase = Opt(args, "--key-pass");
        variant = ParseVariant(variant_text);

        store = new CertStore(data_root);
        server_id = store.FindServerForCert(cert_id);
        if (server_id is null) { output.WriteLine($"no stored certificate '{cert_id}'"); return 2; }

        if (!BuildClient(server_id, data_root, output, out client, out stored)) { return 2; }

        if (variant == RenewalVariant.Proper) {
            result = client.RenewCertificate(cert_id, store, new UseRecordLog(data_root));
        } else {
            // Non-default variant: load + renew explicitly (lineage still recorded by RenewCertificate path only for Proper).
            result = RunRenewVariant(client, store, data_root, cert_id, variant, encrypt ? (passphrase ?? string.Empty) : null, output);
        }

        if (result.IsOk && result.Value.Certificate is not null) {
            output.WriteLine($"renewed: {result.Value.Certificate.Subject} -> {result.Value.Certificate.Thumbprint.ToLowerInvariant()}");
            return 0;
        }
        output.WriteLine($"FAILED: {result.Status} {result.Error} (failInfo {result.Value?.FailInfo})");
        return 1;
    }

    private static ScepResult<EnrollOutcome> RunRenewVariant(ScepClient client, CertStore store, string data_root, string cert_id, RenewalVariant variant, string? passphrase, TextWriter output) {
        System.Security.Cryptography.X509Certificates.X509Certificate2 existing_cert;
        IScepKey existing_key;
        CertStore.CertRecord record;
        string load_error;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca_result;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;

        if (!store.Load(client.Server.Id, cert_id, client.Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }
        ca_result = client.GetCaCert();
        if (!ca_result.IsOk) { return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error); }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = variant,
            CaCertificate = ca_result.Value[0],
        };
        result = client.Renew(request);
        if (result.IsOk && result.Value.Certificate is not null && result.Value.SubjectKey is not null) {
            store.Save(client.Server.Id, result.Value.Certificate, result.Value.SubjectKey, client.Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: result.Value.TransactionId, passphrase: passphrase);
        }
        return result;
    }

    private static int RunGetCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? serial;
        ScepResult<System.Security.Cryptography.X509Certificates.X509Certificate2> result;

        if (args.Length < 2) { output.WriteLine("usage: getcert <serverId> --issuer <dn> --serial <hex>"); return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCert(issuer!, serial!);
        if (!result.IsOk) { output.WriteLine($"getcert failed: {result.Status} {result.Error}"); return 1; }
        output.WriteLine($"found: {result.Value.Subject} (serial {result.Value.SerialNumber})");
        return 0;
    }

    private static int RunGetCrl(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? serial;
        ScepResult<byte[]> result;

        if (args.Length < 2) { output.WriteLine("usage: getcrl <serverId> --issuer <dn> --serial <hex>"); return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCrl(issuer!, serial!);
        if (!result.IsOk) { output.WriteLine($"getcrl failed: {result.Status} {result.Error}"); return 1; }
        output.WriteLine($"CRL: {result.Value.Length} bytes");
        return 0;
    }

    private static int RunPoll(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? subject;
        string? txn;
        ScepResult<EnrollOutcome> result;

        if (args.Length < 2) { output.WriteLine("usage: poll <serverId> --issuer <dn> --subject <dn> --txn <id>"); return 2; }
        issuer = Opt(args, "--issuer");
        subject = Opt(args, "--subject");
        txn = Opt(args, "--txn");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(txn)) { output.WriteLine("--issuer, --subject and --txn are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.Poll(issuer!, subject!, txn!);
        if (result.IsOk && result.Value.Certificate is not null) {
            output.WriteLine($"polled: {result.Value.Certificate.Subject}");
            return 0;
        }
        output.WriteLine($"poll status: {result.Status} (pkiStatus {result.Value?.PkiStatus})");
        return result.Status == ScepClientResult.Pending ? 0 : 1;
    }

    private static RenewalVariant ParseVariant(string? text) {
        switch (text) {
            case "reenroll-same-subject": return RenewalVariant.ReenrollSameSubject;
            case "pkcsreq-old-cert": return RenewalVariant.RenewalShapedPkcsReq;
            case "same-key": return RenewalVariant.SameKey;
            case "expired": return RenewalVariant.Expired;
            default: return RenewalVariant.Proper;
        }
    }

    private static bool HasFlag(string[] args, string flag) {
        int i;

        for (i = 0; i < args.Length; i++) {
            if (args[i] == flag) { return true; }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // certs list
    // -------------------------------------------------------------------------

    private static int RunCerts(string[] args, string data_root, TextWriter output) {
        string verb;
        string? server_id;

        if (args.Length < 2 || args[1] == "list") {
            server_id = args.Length >= 3 ? args[2] : null;
            return RunCertsList(data_root, server_id, output);
        }

        verb = args[1];
        output.WriteLine($"unknown certs sub-command '{verb}'");
        return WriteUsage(output);
    }

    private static int RunCertsList(string data_root, string? server_id, TextWriter output) {
        string servers_root;

        servers_root = Path.Combine(data_root, "servers");

        if (!Directory.Exists(servers_root)) {
            return 0;
        }

        if (!string.IsNullOrEmpty(server_id)) {
            PrintCertsForServer(servers_root, server_id, output);
        } else {
            string[] server_dirs;
            server_dirs = Directory.GetDirectories(servers_root);
            foreach (string server_dir in server_dirs) {
                PrintCertsForServer(servers_root, Path.GetFileName(server_dir), output);
            }
        }

        return 0;
    }

    private static void PrintCertsForServer(string servers_root, string server_id, TextWriter output) {
        string certs_dir;
        string[] cert_dirs;

        certs_dir = Path.Combine(servers_root, server_id, "certificates");
        if (!Directory.Exists(certs_dir)) {
            return;
        }

        cert_dirs = Directory.GetDirectories(certs_dir);
        foreach (string cert_dir in cert_dirs) {
            output.WriteLine($"{server_id}/{Path.GetFileName(cert_dir)}");
        }
    }

    // -------------------------------------------------------------------------
    // config show
    // -------------------------------------------------------------------------

    private static int RunConfig(string[] args, string data_root, TextWriter output) {
        ClientConfig config;

        if (args.Length < 2 || args[1] != "show") {
            return WriteUsage(output);
        }

        config = ClientConfig.Load(data_root);
        output.WriteLine($"CryptoProviderPath: {config.CryptoProviderPath ?? "(default)"}");
        output.WriteLine($"KeySpec:            {config.KeySpec}");
        output.WriteLine($"TimeoutSeconds:     {config.TimeoutSeconds}");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Usage
    // -------------------------------------------------------------------------

    private static int WriteUsage(TextWriter output) {
        output.WriteLine("usage: sceptest [--data-dir <path>] <command> [options]");
        output.WriteLine();
        output.WriteLine("Commands:");
        output.WriteLine("  servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get|post]");
        output.WriteLine("  servers list");
        output.WriteLine("  servers show <id>");
        output.WriteLine("  getcacaps <serverId>");
        output.WriteLine("  get <serverId> --subject \"CN=x\" [--challenge <pw>] [--key-spec rsa:2048] [--sid <s>] [-v]");
        output.WriteLine("  certs list [serverId]");
        output.WriteLine("  getcacert <serverId>");
        output.WriteLine("  getnextcacert <serverId>");
        output.WriteLine("  enroll <serverId> --subject \"CN=x\" [--challenge <pw>] [--key-spec rsa:2048] [--encrypt-keys --key-pass <pw>]");
        output.WriteLine("  renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--encrypt-keys --key-pass <pw>]");
        output.WriteLine("  getcert <serverId> --issuer <dn> --serial <hex>");
        output.WriteLine("  getcrl <serverId> --issuer <dn> --serial <hex>");
        output.WriteLine("  poll <serverId> --issuer <dn> --subject <dn> --txn <id>");
        output.WriteLine("  config show");
        return 2;
    }

    // -------------------------------------------------------------------------
    // Option helpers
    // -------------------------------------------------------------------------

    private static string? Opt(string[] args, string name) {
        int i;

        for (i = 0; i < args.Length - 1; i++) {
            if (args[i] == name) {
                return args[i + 1];
            }
        }

        return null;
    }

    private static int CountFlag(string[] args, string flag) {
        int count;
        int i;

        count = 0;
        for (i = 0; i < args.Length; i++) {
            if (args[i] == flag) {
                count++;
            }
        }

        return count;
    }

    // -------------------------------------------------------------------------
    // ID derivation
    // -------------------------------------------------------------------------

    private static string DeriveId(string url, string? name) {
        string slug;

        if (!string.IsNullOrWhiteSpace(name)) {
            return Slugify(name);
        }

        try {
            Uri uri;
            string host;
            string last_segment;

            uri = new Uri(url);
            host = uri.Host;
            last_segment = uri.Segments.Length > 0 ? uri.Segments[uri.Segments.Length - 1].Trim('/') : string.Empty;

            slug = string.IsNullOrEmpty(last_segment) ? Slugify(host) : Slugify(host + "-" + last_segment);
        } catch {
            slug = Slugify(url);
        }

        return slug;
    }

    private static string Slugify(string text) {
        string lower;
        string result;

        lower = text.ToLowerInvariant();
        result = Regex.Replace(lower, @"[^a-z0-9\-]", "-");
        result = Regex.Replace(result, @"-{2,}", "-");
        result = result.Trim('-');

        if (string.IsNullOrEmpty(result)) {
            result = "server";
        }

        return result;
    }
}
