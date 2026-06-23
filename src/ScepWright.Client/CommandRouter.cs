using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using ScepWright.Core;
using ScepWright.Core.Protocol;
using ScepWright.Core.Recipients;
using ScepWright.Core.Storage;
using ScepWright.Crypto;

namespace ScepWright.Client;

/// <summary>Parses the scepclient command line and dispatches to the matching verb handler.</summary>
public static class CommandRouter {
    /// <summary>Runs the client command line and returns a process exit code.</summary>
    /// <param name="args">The command-line arguments, beginning with the verb.</param>
    /// <param name="data_root">The root directory holding server registrations, certificates and config.</param>
    /// <param name="output">The writer that receives command output.</param>
    /// <returns>A process exit code: 0 on success, non-zero on failure.</returns>
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

            case "diagnose":
            case "doctor":
                return RunDiagnose(args, data_root, output);

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

            case "test":
                return RunTest(args, data_root, output);

            // The suite verbs are also first-class nouns, so `scepwright test full <server>`
            // works without doubling the word `test` (the dispatcher already consumed one).
            case "lifecycle":
            case "full":
            case "probe":
                return RunTestSuite(noun, args.Length > 1 ? args[1] : null, args, data_root, output);

            case "run":
                return RunScenario(args, data_root, output);

            case "certs":
                return RunCerts(args, data_root, output);

            case "config":
                return RunConfig(args, data_root, output);

            case "crypto":
                return CryptoCommand.Run(args, data_root, output);

            case "version":
            case "--version":
                output.WriteLine($"scepclient {ToolVersionString()}");
                return 0;

            case "--help":
            case "-h":
            case "help":
                return WriteUsage(output);

            default:
                output.WriteLine($"unknown command '{noun}'");
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
                return RunServersList(args, data_root, output);

            case "show":
                return RunServersShow(args, data_root, output);

            case "suggest":
                return RunServersSuggest(args, data_root, output);

            default:
                output.WriteLine($"unknown servers sub-command '{verb}'");
                return WriteUsage(output);
        }
    }

    private static int RunServersSuggest(string[] args, string data_root, TextWriter output) {
        string server_id;
        ScepClient client;
        StoredServer stored;
        ScepCapabilities caps;
        System.Collections.Generic.IReadOnlyList<string> lines;
        ClientConfig config;
        ScepWright.Core.Testing.OpinionThresholds thresholds;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> ca_for_suggest;
        RecipientSelection suggest_selection;
        bool can_enroll;

        if (args.Length < 3) { output.WriteLine("usage: servers suggest <id>"); return 2; }
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }
        server_id = args[2];
        if (!BuildClient(args, server_id, data_root, output, out client, out stored)) { return 2; }
        config = ClientConfig.Load(data_root);
        caps = client.GetCaCaps().Value ?? ScepCapabilities.Parse(string.Empty);

        // Diagnosis-aware: if the server presents no encryption-capable recipient, every enroll command
        // below would fail to envelope — warn and skip the enroll suggestions rather than mislead.
        ca_for_suggest = client.GetCaCert();
        can_enroll = false;
        if (ca_for_suggest.IsOk) {
            suggest_selection = RecipientSelector.Select(ca_for_suggest.Value);
            can_enroll = suggest_selection.CanEnvelope && suggest_selection.EncryptionCertificate is not null;
        }

        if (!can_enroll) {
            output.WriteLine($"⚠  no encryption-capable recipient — this server cannot receive SCEP PKIOperation requests, so enrollment would fail. Run `diagnose {server_id}` for details. (Skipping enroll suggestions.)");
        } else {
            lines = ScepWright.Core.Testing.ServerSuggest.For(server_id, caps, client.Crypto.Capabilities, config.MinRsaKeyBits);
            foreach (string line in lines) { output.WriteLine(line); }
        }

        thresholds = new ScepWright.Core.Testing.OpinionThresholds { MinRsaKeyBits = config.MinRsaKeyBits };

        if (caps.Sha256) { output.WriteLine($"posture: SHA-256  {ScepWright.Core.Testing.SecurityOpinion.ClassifyDigest("SHA-256")}"); }
        if (caps.Sha512) { output.WriteLine($"posture: SHA-512  {ScepWright.Core.Testing.SecurityOpinion.ClassifyDigest("SHA-512")}"); }
        if (caps.Sha1) { output.WriteLine($"posture: SHA-1  {ScepWright.Core.Testing.SecurityOpinion.ClassifyDigest("SHA-1")}"); }
        if (caps.Aes) { output.WriteLine($"posture: AES-128-CBC  {ScepWright.Core.Testing.SecurityOpinion.ClassifyCipher("AES-128-CBC")}"); }
        if (caps.Des3) { output.WriteLine($"posture: DES-EDE3-CBC  {ScepWright.Core.Testing.SecurityOpinion.ClassifyCipher("DES-EDE3-CBC")}"); }
        output.WriteLine($"posture: RSA-{thresholds.MinRsaKeyBits}  {ScepWright.Core.Testing.SecurityOpinion.ClassifyRsa(thresholds.MinRsaKeyBits, thresholds)}");
        if (client.Crypto.Capabilities.Signatures.Contains("1.2.840.10045.2.1")) {
            output.WriteLine($"posture: ECDSA-P256  {ScepWright.Core.Testing.SecurityOpinion.ClassifySignature("ECDSA-P256")}");
        }
        if (client.Crypto.Capabilities.PqTiers.TierA) {
            output.WriteLine($"posture: ML-DSA-65  {ScepWright.Core.Testing.SecurityOpinion.ClassifySignature("ML-DSA-65")}");
        }
        if (client.Crypto.Capabilities.PqTiers.TierB) {
            output.WriteLine($"posture: SLH-DSA-192f  {ScepWright.Core.Testing.SecurityOpinion.ClassifySignature("SLH-DSA-192f")}");
        }
        // A server with no encryption-capable recipient can't enroll; reflect that in the exit code so
        // callers (and CI) see the same broken-server signal `diagnose` reports, not a misleading 0.
        return can_enroll ? 0 : 1;
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

        if (!RejectUnknownFlags(args, output, new[] { "--name", "--ca-identifier", "--transport" }, System.Array.Empty<string>())) { return 2; }

        url = args[2];
        // The URL is positional; a flag-looking token here (e.g. `servers add --help`) is a mistake, not a
        // URL — reject it instead of registering a bogus server named after the flag.
        if (url.Length > 0 && url[0] == '-') {
            output.WriteLine("usage: servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get|post]");
            return 2;
        }
        name = Opt(args, "--name");
        ca_identifier = Opt(args, "--ca-identifier");
        transport = Opt(args, "--transport");
        if (transport != null && !string.Equals(transport, "get", StringComparison.OrdinalIgnoreCase) && !string.Equals(transport, "post", StringComparison.OrdinalIgnoreCase)) {
            output.WriteLine($"unknown --transport '{transport}' (expected get|post)");
            return 2;
        }

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

    private static int RunServersList(string[] args, string data_root, TextWriter output) {
        ServerRegistry registry;
        IReadOnlyList<StoredServer> servers;

        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }
        registry = new ServerRegistry(data_root);
        servers = registry.List();

        foreach (StoredServer server in servers) {
            output.WriteLine($"{server.Id}\t{server.Url}");
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
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }

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
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }

        server_id = args[1];
        registry = new ServerRegistry(data_root);
        stored = registry.Get(server_id);

        if (stored is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return 2;
        }

        load_result = ScepCrypto.Load(ResolveProviderPath(args, data_root), out crypto, out crypto_error);
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
        string? alt_key_spec_str;
        string? sid;
        int verbosity;
        bool encrypt_keys;
        string? key_pass;
        string digest_oid;
        string cipher_oid;
        string alg_error;
        ServerRegistry registry;
        StoredServer? stored;
        IScepCrypto crypto;
        string crypto_error;
        ScepClientResult load_result;
        KeySpec spec;
        string key_spec_error;
        IScepKey key;
        string key_error;
        IScepKey? alt_key;
        ScepClient client;
        string client_error;
        ScepClientResult create_result;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;
        ServerConfig config;
        ConsoleTrace tracer;
        System.Net.Http.HttpClient http;
        string challenge_error;
        ClientConfig get_config;

        if (args.Length < 2) {
            output.WriteLine("usage: get <serverId> --subject \"CN=x\" [--dns <name> ...] [--upn <user@dom> ...] [--eku <clientAuth|serverAuth|oid> ...] [--challenge <pw>] [--simulator <url>] [--ndes --ndes-user <u> --ndes-password <p> [--ndes-admin-url <url>]] [--key-spec <rsa:2048|ec:p256|ml-dsa:65|slh-dsa:192f>] [--alt-key-spec ml-dsa:65] [--encrypt-keys --key-pass <pw>] [--sid <s>] [-v]");
            return 2;
        }

        if (!RejectUnknownFlags(args, output,
                new[] { "--subject", "--challenge", "--simulator", "--ndes-user", "--ndes-password", "--ndes-admin-url",
                        "--key-spec", "--alt-key-spec", "--sid", "--key-pass", "--digest", "--cipher", "--dns", "--upn", "--eku" },
                new[] { "--ndes", "--encrypt-keys", "-v" })) {
            return 2;
        }

        server_id = args[1];
        subject = Opt(args, "--subject");
        challenge = null;
        get_config = ClientConfig.Load(data_root);
        key_spec_str = Opt(args, "--key-spec") ?? get_config.KeySpec;
        alt_key_spec_str = Opt(args, "--alt-key-spec");
        sid = Opt(args, "--sid");
        verbosity = CountFlag(args, "-v");
        encrypt_keys = HasFlag(args, "--encrypt-keys");
        key_pass = null;

        if (string.IsNullOrWhiteSpace(subject)) {
            output.WriteLine("--subject is required");
            return 2;
        }

        if (!ResolveAlgOid(Opt(args, "--digest"), "SHA-256", out digest_oid, out alg_error)) {
            output.WriteLine($"invalid --digest: {alg_error}");
            return 2;
        }
        if (!ResolveAlgOid(Opt(args, "--cipher"), "AES-128-CBC", out cipher_oid, out alg_error)) {
            output.WriteLine($"invalid --cipher: {alg_error}");
            return 2;
        }

        if (encrypt_keys) {
            key_pass = PassphrasePrompt.Resolve(Opt(args, "--key-pass"), "Key passphrase");
        }
        if (encrypt_keys && string.IsNullOrEmpty(key_pass)) {
            output.WriteLine("--encrypt-keys requires a passphrase (--key-pass, $SCEPWRIGHT_KEY_PASS, or prompt)");
            return 2;
        }

        registry = new ServerRegistry(data_root);
        stored = registry.Get(server_id);

        if (stored is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return 2;
        }

        http = new System.Net.Http.HttpClient();
        if (!ResolveChallenge(args, stored.Url, http, out challenge, out challenge_error)) {
            output.WriteLine($"challenge resolution failed: {challenge_error}");
            return 1;
        }
        if (challenge != null) {
            output.WriteLine($"challenge: {Redaction.Hash(challenge)}");
        }

        load_result = ScepCrypto.Load(ResolveProviderPath(args, data_root), out crypto, out crypto_error);
        if (load_result != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return 1;
        }

        if (!KeySpec.Parse(key_spec_str, out spec, out key_spec_error)) {
            output.WriteLine($"invalid key spec: {key_spec_error}");
            return 2;
        }

        if (spec.Algorithm == "RSA" && spec.Size < get_config.MinRsaKeyBits) {
            output.WriteLine($"key-spec {key_spec_str} is below the configured min-rsa-bits floor ({get_config.MinRsaKeyBits}); raise the key size or lower the floor with `config set min-rsa-bits`");
            return 2;
        }

        if (!crypto.GenerateKey(spec, out key, out key_error)) {
            output.WriteLine($"key generation failed: {key_error}");
            return 1;
        }

        alt_key = null;
        if (!string.IsNullOrWhiteSpace(alt_key_spec_str)) {
            KeySpec alt_spec;
            string alt_spec_error;
            string alt_key_error;

            if (!KeySpec.Parse(alt_key_spec_str!, out alt_spec, out alt_spec_error)) {
                output.WriteLine($"invalid alt key spec: {alt_spec_error}");
                return 2;
            }

            if (!crypto.GenerateKey(alt_spec, out alt_key, out alt_key_error)) {
                output.WriteLine($"alt key generation failed: {alt_key_error}");
                return 1;
            }
            // Disclose at runtime (not just in --help): this is an experimental, non-conformant probe.
            output.WriteLine($"note: --alt-key-spec {alt_key_spec_str} is an EXPERIMENTAL non-conformant probe — the alt key is attached to the CSR but no altSignatureValue is computed and the alt key is NOT retained.");
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
            AltKey = alt_key,
            ChallengePassword = challenge,
            Sid = sid,
            KeySpecText = key_spec_str,
            DigestOid = digest_oid,
            ContentEncryptionOid = cipher_oid,
        };
        foreach (string dns in OptAll(args, "--dns")) {
            // RFC 5280 dNSName is a non-empty IA5String; an empty/blank value would mint an invalid "DNS:" SAN.
            if (string.IsNullOrWhiteSpace(dns)) { output.WriteLine("--dns value must not be empty or blank (RFC 5280 dNSName must be a non-empty name)"); return 2; }
            request.DnsNames.Add(dns);
        }
        foreach (string upn in OptAll(args, "--upn")) {
            if (string.IsNullOrWhiteSpace(upn)) { output.WriteLine("--upn value must not be empty or blank"); return 2; }
            request.Upns.Add(upn);
        }
        foreach (string eku in OptAll(args, "--eku")) { request.Ekus.Add(eku); }

        outcome = client.GetNewCertificate(request, new CertStore(data_root), new UseRecordLog(data_root), key_passphrase: encrypt_keys ? key_pass : null);

        if (outcome.IsOk) {
            System.Security.Cryptography.X509Certificates.X509Certificate2? cert;

            cert = outcome.Value.Certificate;
            output.WriteLine($"issued: {cert?.Subject ?? "(no certificate)"}");
            if (cert is not null) {
                string cert_dir;
                cert_dir = Path.GetFullPath(Path.Combine(data_root, "servers", stored.Id, "certificates", cert.Thumbprint.ToLowerInvariant()));
                output.WriteLine($"  certId:    {stored.Id}/{cert.Thumbprint.ToLowerInvariant()}   (use with `renew` / `certs export`)");
                output.WriteLine($"  stored in: {cert_dir}");
                output.WriteLine($"             cert.pem + {(encrypt_keys ? "key.pkcs8.enc (encrypted)" : "key.pkcs8")}");
                if (!encrypt_keys) {
                    output.WriteLine("  note: the private key is stored UNENCRYPTED — re-run with --encrypt-keys --key-pass <pw> to protect it at rest.");
                }
            }
            return 0;
        }

        if (outcome.Status == ScepClientResult.Pending) {
            string pending_txn;

            // Persist the subject key + request so `poll` can later sign the CertPoll with this key
            // (RFC 8894 §3.3.2) and store the issued cert paired with it. Without this the polled cert
            // would have no matching key and never appear in `certs list`.
            pending_txn = outcome.Value?.TransactionId ?? string.Empty;
            if (pending_txn.Length > 0) {
                new PendingStore(data_root).Save(stored.Id, pending_txn, request.Key, client.Crypto,
                    key_spec_text: request.KeySpecText, passphrase: encrypt_keys ? key_pass : null);
            }
            return ReportPending(client, outcome.Value, subject!, output);
        }

        output.WriteLine(FormatFailure(outcome));
        return 1;
    }

    // PENDING is the CA holding the request for manual approval — not a failure. Surface the
    // transaction id and a ready-to-run poll command so the CertPoll flow can be completed by hand.
    private static int ReportPending(ScepClient client, EnrollOutcome? outcome, string subject, TextWriter output) {
        string txn;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;
        string issuer;

        txn = outcome?.TransactionId ?? "(unknown)";
        output.WriteLine("PENDING: the CA is holding this request for manual approval (no certificate issued yet).");
        output.WriteLine($"  transaction id: {txn}");

        ca = client.GetCaCert();
        issuer = ca.IsOk && ca.Value.Count > 0 ? ca.Value[0].Subject : "<CA subject>";

        output.WriteLine("  poll for the result once approved with:");
        output.WriteLine($"    poll {client.Server.Id} --issuer \"{issuer}\" --subject \"{subject}\" --txn {txn}");
        return 0;
    }

    // Names the SCEP failInfo so a rejection says *why* (e.g. badRequest for a wrong challenge),
    // rather than the redundant "ServerFailure ... Failure".
    private static string FormatFailure(ScepResult<EnrollOutcome> result) {
        EnrollOutcome? value;

        value = result.Value;
        if (value is not null && value.PkiStatus == PkiStatus.Failure) {
            if (value.FailInfo == FailInfo.None) {
                return "FAILED: CA rejected the request (no failInfo provided)";
            }
            string hint;
            hint = value.FailInfo == FailInfo.BadRequest
                ? "  (badRequest often means a wrong/missing challenge password — pass --challenge — or a CA policy rejection)"
                : string.Empty;
            return $"FAILED: CA rejected the request (failInfo: {FailInfoName(value.FailInfo)}){hint}";
        }
        return $"FAILED: {result.Status}: {result.Error}";
    }

    private static string FailInfoName(FailInfo info) {
        switch (info) {
            case FailInfo.BadAlg: return "badAlg";
            case FailInfo.BadMessageCheck: return "badMessageCheck";
            case FailInfo.BadRequest: return "badRequest";
            case FailInfo.BadTime: return "badTime";
            case FailInfo.BadCertId: return "badCertId";
            default: return "none";
        }
    }

    // Resolves a friendly digest/cipher name (e.g. "SHA-256", "AES-128-CBC") to its OID, falling
    // back to the supplied default when the flag was not given.
    private static bool ResolveAlgOid(string? name, string default_name, out string oid, out string error) {
        string? resolved;

        error = string.Empty;
        if (string.IsNullOrWhiteSpace(name)) {
            oid = Algorithms.OidFor(default_name)!;
            return true;
        }

        resolved = Algorithms.OidFor(name);
        if (resolved is null) {
            oid = string.Empty;
            error = $"unknown algorithm '{name}'";
            return false;
        }
        oid = resolved;
        return true;
    }

    // -------------------------------------------------------------------------
    // getcacert, getnextcacert, renew, getcert, getcrl, poll
    // -------------------------------------------------------------------------

    private static bool BuildClient(string[] args, string server_id, string data_root, TextWriter output, out ScepClient client, out StoredServer stored) {
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

        if (ScepCrypto.Load(ResolveProviderPath(args, data_root), out crypto, out crypto_error) != ScepClientResult.Ok) {
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

        if (args.Length < 2) { output.WriteLine("usage: getcacert <serverId> [-v]"); return 2; }
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), new[] { "-v" })) { return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCaCert();
        if (!result.IsOk) { output.WriteLine($"getcacert failed: {result.Status} {result.Error}"); return 1; }

        if (HasFlag(args, "-v")) {
            int idx;
            idx = 0;
            foreach (X509Certificate2 cert in result.Value) {
                PrintCertDetails(output, cert, result.Value.Count > 1 ? $"GetCACert[{idx}]" : "GetCACert");
                idx++;
            }
        } else {
            foreach (X509Certificate2 cert in result.Value) {
                output.WriteLine(cert.Subject);
            }
        }
        return 0;
    }

    // Read-only health check: caps, every CA/RA cert's details, and whether SCEP requests can actually
    // be enveloped to a recipient — the diagnostic Roz needs to spot a wrong RA/CA cert without enrolling.
    private static int RunDiagnose(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<ScepCapabilities> caps;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> ca;
        RecipientSelection selection;
        int idx;
        int verbosity;
        ConsoleTrace tracer;
        System.Collections.Generic.List<string> cap_warnings;

        if (args.Length < 2) { output.WriteLine("usage: diagnose <serverId> [-v]"); return 2; }
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), new[] { "-v" })) { return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

        verbosity = CountFlag(args, "-v");
        if (verbosity > 0) {
            tracer = new ConsoleTrace(verbosity);
            client.Trace += tracer.Handle;
        }

        output.WriteLine($"diagnose {stored.Id}  ({stored.Url})");
        output.WriteLine();

        caps = client.GetCaCaps();
        output.WriteLine(caps.IsOk
            ? $"GetCACaps: {string.Join(", ", caps.Value.RawKeywords)}"
            : $"GetCACaps: FAILED ({caps.Status} {caps.Error})");
        output.WriteLine();

        ca = client.GetCaCert();
        if (!ca.IsOk) {
            output.WriteLine($"GetCACert: FAILED ({ca.Status} {ca.Error}) — cannot diagnose further.");
            return 1;
        }

        idx = 0;
        foreach (X509Certificate2 cert in ca.Value) {
            PrintCertDetails(output, cert, ca.Value.Count > 1 ? $"GetCACert[{idx}]" : "GetCACert");
            output.WriteLine();
            idx++;
        }

        selection = RecipientSelector.Select(ca.Value);
        foreach (RecipientFinding finding in selection.Findings) {
            output.WriteLine($"[finding] {finding.Code}: {finding.Message}");
        }

        // Enrollment-capability checks: a server can present a valid recipient yet still be unusable by
        // real clients (e.g. Jamf requires HTTP POST), so judge CACaps too — not just the recipient.
        cap_warnings = new System.Collections.Generic.List<string>();
        if (!caps.IsOk) {
            cap_warnings.Add("GetCACaps failed — cannot confirm the server advertises any capabilities");
        } else {
            if (!caps.Value.PostPkiOperation) { cap_warnings.Add("CACaps lacks POSTPKIOperation — clients that require HTTP POST (e.g. Jamf) will fail"); }
            if (!caps.Value.Sha256 && !caps.Value.Sha512) { cap_warnings.Add("CACaps advertises no SHA-2 digest (SHA-256/SHA-512) — modern clients may refuse to enroll"); }
        }
        foreach (string warning in cap_warnings) {
            output.WriteLine($"[finding] caps: {warning}");
        }

        if (selection.CanEnvelope && selection.EncryptionCertificate is not null) {
            System.Collections.Generic.IReadOnlyList<string> recipient_warnings;

            if (IsKemRecipient(selection.EncryptionCertificate)) {
                output.WriteLine("[info] recipient is an ML-KEM key — requests use RFC 9629 KEMRecipientInfo enveloping.");
            }
            // A temporally-invalid recipient (expired / not-yet-valid) can still be enveloped to, but
            // clients will reject the cert — so it downgrades the verdict rather than reading as OK.
            recipient_warnings = ScepWright.Core.Recipients.RecipientHealth.TemporalWarnings(selection.EncryptionCertificate);
            foreach (string warning in recipient_warnings) {
                output.WriteLine($"[finding] recipient: {warning}");
            }
            if (cap_warnings.Count == 0 && recipient_warnings.Count == 0) {
                output.WriteLine($"VERDICT: OK — requests can be enveloped to '{selection.EncryptionCertificate.Subject}'.");
                return 0;
            }
            output.WriteLine($"VERDICT: PROBLEMS — a recipient exists ('{selection.EncryptionCertificate.Subject}'), but {cap_warnings.Count + recipient_warnings.Count} issue(s) above will break some clients.");
            return 1;
        }
        output.WriteLine("VERDICT: BROKEN — no encryption-capable recipient; this server cannot receive SCEP PKIOperation requests (check the RA/CA encryption cert and its KeyUsage).");
        return 1;
    }

    private static bool IsKemRecipient(X509Certificate2 cert) {
        return cert.GetKeyAlgorithm().StartsWith("2.16.840.1.101.3.4.4", StringComparison.Ordinal);   // ML-KEM OID arc
    }

    private static void PrintCertDetails(TextWriter output, X509Certificate2 cert, string label) {
        output.WriteLine($"{label}:");
        output.WriteLine($"  Subject:    {cert.Subject}");
        output.WriteLine($"  Issuer:     {cert.Issuer}");
        output.WriteLine($"  Serial:     {cert.SerialNumber}");
        output.WriteLine($"  Validity:   {cert.NotBefore.ToUniversalTime():u}  ..  {cert.NotAfter.ToUniversalTime():u}{(cert.NotAfter.ToUniversalTime() < System.DateTime.UtcNow ? "  (EXPIRED)" : string.Empty)}");
        output.WriteLine($"  Thumbprint: {cert.Thumbprint.ToLowerInvariant()}");
        foreach (X509Extension ext in cert.Extensions) {
            if (ext is X509KeyUsageExtension ku) {
                output.WriteLine($"  KeyUsage:   {ku.KeyUsages}");
            } else if (ext is X509EnhancedKeyUsageExtension eku) {
                System.Collections.Generic.List<string> purposes;
                purposes = new System.Collections.Generic.List<string>();
                foreach (System.Security.Cryptography.Oid oid in eku.EnhancedKeyUsages) { purposes.Add(oid.FriendlyName ?? oid.Value ?? "?"); }
                output.WriteLine($"  EKU:        {(purposes.Count > 0 ? string.Join(", ", purposes) : "(none)")}");
            } else if (ext is X509BasicConstraintsExtension bc) {
                output.WriteLine($"  BasicConstraints: CA={bc.CertificateAuthority}");
            }
        }
    }

    private static int RunGetNextCaCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> result;

        if (args.Length < 2) { output.WriteLine("usage: getnextcacert <serverId>"); return 2; }
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetNextCaCert();
        if (!result.IsOk) { output.WriteLine($"getnextcacert failed: {result.Status} {result.Error}"); return 1; }
        foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 cert in result.Value) {
            output.WriteLine(cert.Subject);
        }
        return 0;
    }

    private static int RunRenew(string[] args, string data_root, TextWriter output) {
        string cert_id;
        string? variant_text;
        string? passphrase;
        string? key_spec_override;
        bool encrypt;
        CertStore store;
        string? server_id;
        ScepClient client;
        StoredServer stored;
        ScepResult<EnrollOutcome> result;
        RenewalVariant variant;
        int slash;
        string? renew_challenge;
        string challenge_error;

        if (args.Length < 2) { output.WriteLine("usage: renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--key-spec <rsa:2048|ec:p256|ml-dsa:65|slh-dsa:192f>] [--challenge <pw> | --simulator <url> | --ndes --ndes-user <u> --ndes-password <p>] [--encrypt-keys] [--key-pass <pw>]"); return 2; }

        if (!RejectUnknownFlags(args, output,
                new[] { "--variant", "--key-spec", "--key-pass", "--challenge", "--simulator", "--ndes-user", "--ndes-password", "--ndes-admin-url" },
                new[] { "--encrypt-keys", "--ndes" })) {
            return 2;
        }

        cert_id = args[1];
        // Validate the certId up front: a blank arg ("") would resolve to an arbitrary server, and a blank
        // thumbprint ("server/") collapses to the certificates/ directory whose missing cert.pem then leaks
        // an internal path through the top-level `fatal:` handler. Reject both with a clean message.
        if (string.IsNullOrWhiteSpace(cert_id)) { output.WriteLine("renew: certId must not be empty (pass the serverId/thumbprint or thumbprint shown by `certs list`)"); return 2; }
        variant_text = Opt(args, "--variant");
        if (variant_text != null && !IsKnownVariant(variant_text)) {
            output.WriteLine($"unknown --variant '{variant_text}' (expected proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired)");
            return 2;
        }
        encrypt = HasFlag(args, "--encrypt-keys");
        key_spec_override = Opt(args, "--key-spec");
        variant = ParseVariant(variant_text);

        store = new CertStore(data_root);

        // Accept both the `server/thumbprint` form printed by `certs list` and a bare thumbprint.
        slash = cert_id.IndexOf('/');
        if (slash >= 0) {
            server_id = cert_id.Substring(0, slash);
            cert_id = cert_id.Substring(slash + 1);
        } else {
            server_id = store.FindServerForCert(cert_id);
        }
        // A blank thumbprint after the slash ("server/") or an unresolved server is not a real certificate.
        if (string.IsNullOrEmpty(server_id) || string.IsNullOrEmpty(cert_id)) { output.WriteLine($"no stored certificate '{args[1]}'"); return 2; }

        // An encrypted key must be decrypted to renew — and the renewed key is re-encrypted with the
        // same passphrase so turning on the safety feature never makes a cert un-renewable or silently
        // downgrades it to plaintext.
        passphrase = null;
        if (store.IsKeyEncrypted(server_id, cert_id) || encrypt || Opt(args, "--key-pass") is not null) {
            passphrase = PassphrasePrompt.Resolve(Opt(args, "--key-pass"), "Key passphrase");
            if (store.IsKeyEncrypted(server_id, cert_id) && string.IsNullOrEmpty(passphrase)) {
                output.WriteLine($"certificate '{cert_id}' has an encrypted key; a passphrase is required (--key-pass, $SCEPWRIGHT_KEY_PASS, or prompt)");
                return 2;
            }
        }

        if (!BuildClient(args, server_id, data_root, output, out client, out stored)) { return 2; }

        // Renewal against a challenge-protected CA needs the challenge too (same sources as enroll).
        renew_challenge = null;
        if (!ResolveChallenge(args, stored.Url, new System.Net.Http.HttpClient(), out renew_challenge, out challenge_error)) {
            output.WriteLine($"challenge resolution failed: {challenge_error}");
            return 1;
        }

        // Spec resolution precedence: --key-spec flag > the cert's recorded key-spec > config default.
        key_spec_override = ResolveRenewKeySpec(store, server_id, client, cert_id, data_root, key_spec_override, passphrase);

        if (variant == RenewalVariant.Proper) {
            result = client.RenewCertificate(cert_id, store, new UseRecordLog(data_root), key_spec_override: key_spec_override, passphrase: passphrase, challenge: renew_challenge);
        } else {
            // Non-default variant: load + renew explicitly.
            result = RunRenewVariant(client, store, data_root, cert_id, variant, passphrase, key_spec_override, renew_challenge, output);
        }

        if (result.IsOk && result.Value.Certificate is not null) {
            string new_thumb;
            new_thumb = result.Value.Certificate.Thumbprint.ToLowerInvariant();
            output.WriteLine($"renewed: {result.Value.Certificate.Subject}");
            output.WriteLine($"  certId:    {server_id}/{new_thumb}   (the prior cert is now marked superseded in `certs list`)");
            output.WriteLine($"  stored in: {Path.GetFullPath(Path.Combine(data_root, "servers", server_id, "certificates", new_thumb))}");
            output.WriteLine($"  key at rest: {(store.IsKeyEncrypted(server_id, new_thumb) ? "encrypted (PBES2/AES-256)" : "UNENCRYPTED — re-run with --encrypt-keys --key-pass <pw> to protect it at rest")}");
            if (IsPqSignatureSpec(key_spec_override)) {
                // Disclosure: the re-enroll signed with a transient RSA transport key. Not a PQ downgrade —
                // it protects only the (public) CertRep; the certified key stays ML-DSA/SLH-DSA.
                output.WriteLine("  note: signed with a transient RSA transport key so the CA could envelope the CertRep back; it protects only the public response (your certified key is still PQ).");
            }
            return 0;
        }
        output.WriteLine(FormatFailure(result));
        // A proper RenewalReq is signed by the existing cert; a PQ signature cert (ML-DSA / SLH-DSA)
        // can't receive the enveloped CertRep, so a conformant server rejects it. Point the user at the
        // re-enroll path, which signs with a transient RSA transport key and does succeed.
        if (variant == RenewalVariant.Proper && IsPqSignatureSpec(key_spec_override)) {
            output.WriteLine("  hint: this is a PQ signature certificate — a proper RenewalReq can't envelope the response back to it.");
            output.WriteLine($"        re-enroll instead: renew {server_id}/{cert_id} --variant reenroll-same-subject [--challenge <pw>]");
        }
        return 1;
    }

    private static bool IsPqSignatureSpec(string? key_spec) {
        if (string.IsNullOrEmpty(key_spec)) { return false; }
        return key_spec.StartsWith("ml-dsa", System.StringComparison.OrdinalIgnoreCase)
            || key_spec.StartsWith("slh-dsa", System.StringComparison.OrdinalIgnoreCase);
    }

    // Resolves the key-spec for a renewal: explicit --key-spec flag, else the cert's recorded
    // key-spec, else the configured default. Returns null only if nothing is known (lets the
    // RenewCertificate baseline apply).
    private static string? ResolveRenewKeySpec(CertStore store, string server_id, ScepClient client, string cert_id, string data_root, string? flag, string? passphrase) {
        CertStore.CertRecord record;
        string load_error;
        string? resolved;

        if (!string.IsNullOrEmpty(flag)) { return flag; }

        if (store.Load(server_id, cert_id, client.Crypto, out _, out _, out record, out load_error, passphrase)) {
            if (!string.IsNullOrEmpty(record.KeySpec)) { return record.KeySpec; }
        }

        resolved = ClientConfig.Load(data_root).KeySpec;
        return string.IsNullOrEmpty(resolved) ? null : resolved;
    }

    private static ScepResult<EnrollOutcome> RunRenewVariant(ScepClient client, CertStore store, string data_root, string cert_id, RenewalVariant variant, string? passphrase, string? key_spec, string? challenge, TextWriter output) {
        System.Security.Cryptography.X509Certificates.X509Certificate2 existing_cert;
        IScepKey existing_key;
        CertStore.CertRecord record;
        string load_error;
        string resolved_spec;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;

        if (!store.Load(client.Server.Id, cert_id, client.Crypto, out existing_cert, out existing_key, out record, out load_error, passphrase)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        resolved_spec = key_spec ?? record.KeySpec ?? string.Empty;

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = variant,
            KeySpecText = resolved_spec,
            // CaCertificate left unset: Renew selects the RA encryption recipient itself (Value[0] is the
            // CA signing cert, which is the wrong envelope target for split-RA / PQ CAs).
            ChallengePassword = challenge,
        };
        result = client.Renew(request);
        if (result.IsOk && result.Value.Certificate is not null && result.Value.SubjectKey is not null) {
            store.Save(client.Server.Id, result.Value.Certificate, result.Value.SubjectKey, client.Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: result.Value.TransactionId, passphrase: passphrase,
                key_spec_text: string.IsNullOrEmpty(resolved_spec) ? null : resolved_spec);
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
        if (!RejectUnknownFlags(args, output, new[] { "--issuer", "--serial" }, System.Array.Empty<string>())) { return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

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
        if (!RejectUnknownFlags(args, output, new[] { "--issuer", "--serial" }, System.Array.Empty<string>())) { return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

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
        string? key_pass;
        PendingStore pending;
        IScepKey? original_key;
        PendingStore.PendingRecord? pending_record;
        IScepKey loaded_key;
        PendingStore.PendingRecord loaded_record;
        string load_error;
        ScepResult<EnrollOutcome> result;

        if (args.Length < 2) { output.WriteLine("usage: poll <serverId> --issuer <dn> --subject <dn> --txn <id> [--key-pass <pw>]"); return 2; }
        if (!RejectUnknownFlags(args, output, new[] { "--issuer", "--subject", "--txn", "--key-pass" }, System.Array.Empty<string>())) { return 2; }
        issuer = Opt(args, "--issuer");
        subject = Opt(args, "--subject");
        txn = Opt(args, "--txn");
        key_pass = Opt(args, "--key-pass");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(txn)) { output.WriteLine("--issuer, --subject and --txn are required"); return 2; }
        if (!BuildClient(args, args[1], data_root, output, out client, out stored)) { return 2; }

        // Recover the original enrollment key for this transaction (saved when the request went PENDING),
        // so the CertPoll is signed with it (RFC 8894 §3.3.2) and the issued cert can be stored as a
        // usable cert+key pair that shows up in `certs list`.
        pending = new PendingStore(data_root);
        original_key = null;
        pending_record = null;
        if (pending.TryLoad(stored.Id, txn!, client.Crypto, out loaded_key, out loaded_record, out load_error, passphrase: key_pass)) {
            original_key = loaded_key;
            pending_record = loaded_record;
        } else if (Directory.Exists(Path.Combine(data_root, "servers", stored.Id, "pending", txn!))) {
            output.WriteLine($"note: {load_error} — polling without it; the issued cert will NOT be stored.");
        }

        result = client.Poll(issuer!, subject!, txn!, original_key);
        if (result.IsOk && result.Value.Certificate is not null) {
            output.WriteLine($"polled: {result.Value.Certificate.Subject}");
            if (original_key is not null) {
                string cert_id;

                cert_id = new CertStore(data_root).Save(stored.Id, result.Value.Certificate, original_key, client.Crypto,
                    challenge_password: null, renewed_from: null, transaction_id: txn,
                    passphrase: string.IsNullOrEmpty(key_pass) ? null : key_pass, key_spec_text: pending_record?.KeySpec);
                pending.Delete(stored.Id, txn!);
                output.WriteLine($"  stored: {stored.Id}/{cert_id}   (now in `certs list`; use with `renew` / `certs export`)");
            } else {
                output.WriteLine("  note: no pending enrollment found for this --txn, so the cert was received but NOT stored (no matching private key). Run the original `get`/`enroll` first.");
            }
            return 0;
        }
        output.WriteLine($"poll status: {result.Status} (pkiStatus {result.Value?.PkiStatus})");
        return result.Status == ScepClientResult.Pending ? 0 : 1;
    }

    // -------------------------------------------------------------------------
    // test lifecycle/full/probe
    // -------------------------------------------------------------------------

    private static int RunTest(string[] args, string data_root, TextWriter output) {
        if (args.Length < 3) { output.WriteLine("usage: test <lifecycle|full|probe> <server> [--dry-run] [--report-format junit|trx|json|md] [--jamf-max-wait <ms>] [--challenge <pw> | --simulator <url> | --ndes --ndes-user <u> --ndes-password <p>] [--fail-on-findings]"); return 2; }
        return RunTestSuite(args[1], args[2], args, data_root, output);
    }

    private static int RunTestSuite(string verb, string? server_id, string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepWright.Core.Testing.TestEngine engine;
        ScepWright.Core.Testing.TestReport report;
        System.Collections.Generic.List<string> formats;
        string? challenge;
        string challenge_error;

        // Validate the verb BEFORE building a client or printing the blast-radius banner, so an unknown
        // verb (e.g. `test diagnose`) never claims "issues REAL certificates". diagnose is read-only and
        // not a suite verb — point the user at running it directly.
        if (verb != "lifecycle" && verb != "full" && verb != "probe") {
            if (verb == "diagnose") {
                output.WriteLine($"diagnose is a read-only command, not a `test` suite — run it directly: diagnose {server_id}");
            } else {
                output.WriteLine($"unknown test verb '{verb}' (expected lifecycle|full|probe)");
            }
            return 2;
        }

        if (string.IsNullOrEmpty(server_id)) { output.WriteLine($"usage: {verb} <server> [--dry-run] [--report-format junit|trx|json|md] [--jamf-max-wait <ms>] [--challenge <pw> | --simulator <url> | --ndes --ndes-user <u> --ndes-password <p> [--ndes-admin-url <url>]] [--fail-on-findings]"); return 2; }
        if (!RejectUnknownFlags(args, output,
                new[] { "--report-format", "--jamf-max-wait", "--challenge", "--simulator", "--ndes-user", "--ndes-password", "--ndes-admin-url" },
                new[] { "--fail-on-findings", "--ndes", "--dry-run" })) { return 2; }
        if (!ValidateReportFormats(args, output)) { return 2; }

        if (!BuildClient(args, server_id, data_root, output, out client, out stored)) { return 2; }

        engine = new ScepWright.Core.Testing.TestEngine();

        // --dry-run: read-only mode. Run only the checks that don't enroll/renew, so it's safe to point
        // at a CA you don't own (no certificates issued). Skips the blast-radius banner and the challenge.
        if (HasFlag(args, "--dry-run")) {
            output.WriteLine($"ℹ  {verb} --dry-run: read-only checks only on '{stored.Id}' ({stored.Url}); NO certificates are issued.");
            output.WriteLine();
            report = engine.RunDryRun(client);
            StampReport(report, stored, client);
            output.Write(ScepWright.Core.Reporting.ConsoleSummary.Emit(report));
            formats = OptAll(args, "--report-format");
            WriteReports(report, formats, data_root, server_id, output, HasFlag(args, "--fail-on-findings"));
            return TestExitCode(report, args);
        }

        // A challenge-protected / NDES CA needs the challenge plumbed into every enroll the suite makes
        // (same sources as enroll/renew); without it the enroll probes fail for a config reason, not a defect.
        challenge = null;
        if (!ResolveChallenge(args, stored.Url, new System.Net.Http.HttpClient(), out challenge, out challenge_error)) {
            output.WriteLine($"challenge resolution failed: {challenge_error}");
            return 1;
        }

        // Blast-radius disclosure: these suites enroll/renew REAL certificates on the target CA.
        output.WriteLine($"⚠  {verb} issues (and renews) REAL certificates on '{stored.Id}' ({stored.Url}).");
        output.WriteLine("   Safe against an UNTRUSTED test CA; do NOT run against a production CA you don't own. For a read-only check use `diagnose` or `--dry-run`.");
        output.WriteLine();

        switch (verb) {
            case "lifecycle":
                ScepWright.Core.Storage.CertStore store;
                ScepWright.Core.Storage.UseRecordLog log;

                store = new ScepWright.Core.Storage.CertStore(data_root);
                log = new ScepWright.Core.Storage.UseRecordLog(data_root);
                report = engine.RunLifecycle(client, store, log, challenge);
                break;

            case "full":
                report = RunFullWithOptionalJamf(args, client, challenge, output);
                break;

            case "probe":
                report = engine.RunProbe(client, challenge);
                break;

            default:
                output.WriteLine("usage: test <lifecycle|full|probe> <server>");
                return 2;
        }

        StampReport(report, stored, client);
        output.Write(ScepWright.Core.Reporting.ConsoleSummary.Emit(report));
        formats = OptAll(args, "--report-format");
        WriteReports(report, formats, data_root, server_id, output, HasFlag(args, "--fail-on-findings"));
        return TestExitCode(report, args);
    }

    // Clean informational version (e.g. "1.0.0") rather than the 4-part assembly default "1.0.0.0".
    internal static string ToolVersionString() {
        System.Reflection.Assembly asm;
        System.Reflection.AssemblyInformationalVersionAttribute? info;

        asm = typeof(CommandRouter).Assembly;
        info = System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm);
        return string.IsNullOrEmpty(info?.InformationalVersion)
            ? (asm.GetName().Version?.ToString() ?? "unknown")
            : info!.InformationalVersion;
    }

    // Stamps attribution into the report so the md/json/junit files are defensible audit evidence
    // (not just a filename): when it ran, against what, with which tool version, and the CA fingerprint.
    private static void StampReport(ScepWright.Core.Testing.TestReport report, StoredServer stored, ScepClient client) {
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;

        report.GeneratedUtc = System.DateTime.UtcNow;
        report.ToolVersion = ToolVersionString();
        report.TargetUrl = stored.Url;
        ca = client.GetCaCert();
        if (ca.IsOk && ca.Value.Count > 0) {
            report.CaThumbprint = ca.Value[0].Thumbprint.ToLowerInvariant();
        }
    }

    // Exit non-zero on any failed check; also on leniency findings when --fail-on-findings is set
    // (so CI can gate on a strict-but-RFC-compliant server).
    private static int TestExitCode(ScepWright.Core.Testing.TestReport report, string[] args) {
        if (report.Failed > 0) { return 1; }
        if (HasFlag(args, "--fail-on-findings") && report.Findings > 0) {
            return 1;
        }
        return 0;
    }

    private static ScepWright.Core.Testing.TestReport RunFullWithOptionalJamf(string[] args, ScepClient client, string? challenge, TextWriter output) {
        ScepWright.Core.Testing.TestEngine engine;
        ScepWright.Core.Testing.TestReport report;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;
        ScepWright.Core.Protocol.ScepCapabilities caps;
        string? jamf;

        engine = new ScepWright.Core.Testing.TestEngine();
        ca = client.GetCaCert();
        if (!ca.IsOk) {
            output.WriteLine($"getcacert failed: {ca.Status} {ca.Error}");
            report = new ScepWright.Core.Testing.TestReport { ServerId = client.Server.Id, Mode = "full" };
            report.Results.Add(new ScepWright.Core.Testing.CheckResult("GetCACert", ScepWright.Core.Testing.CheckOutcome.Failed,
                FailInfo.None, FailInfo.None, PkiStatus.Failure, $"GetCACert failed: {ca.Error}", "RFC 8894", System.TimeSpan.Zero));
            return report;
        }
        caps = client.GetCaCaps().Value ?? ScepWright.Core.Protocol.ScepCapabilities.Parse(string.Empty);
        report = engine.RunFull(client, ca.Value, caps, challenge);

        jamf = Opt(args, "--jamf-max-wait");
        if (jamf != null && int.TryParse(jamf, out int ms)) {
            AppendJamfStep(report, client, ca.Value, challenge, ms, output);
        }
        return report;
    }

    private static void AppendJamfStep(ScepWright.Core.Testing.TestReport report, ScepClient client, System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> ca_bundle, string? challenge, int ms, TextWriter output) {
        KeySpec spec;
        string key_spec_error;
        IScepKey key;
        string key_error;
        EnrollRequest request;
        ScepWright.Core.Testing.JamfResult result;
        ScepWright.Core.Recipients.RecipientSelection selection;
        System.Security.Cryptography.X509Certificates.X509Certificate2 recipient;
        string issuer_dn;

        // Deliberate baseline probe: the Jamf timing check uses a fixed rsa:2048 key.
        if (!KeySpec.Parse("rsa:2048", out spec, out key_spec_error)) {
            report.Results.Add(new ScepWright.Core.Testing.CheckResult("jamf timing", ScepWright.Core.Testing.CheckOutcome.Failed,
                FailInfo.None, FailInfo.None, PkiStatus.Failure, $"key spec error: {key_spec_error}", "Jamf", System.TimeSpan.Zero));
            return;
        }
        if (!client.Crypto.GenerateKey(spec, out key, out key_error)) {
            report.Results.Add(new ScepWright.Core.Testing.CheckResult("jamf timing", ScepWright.Core.Testing.CheckOutcome.Failed,
                FailInfo.None, FailInfo.None, PkiStatus.Failure, $"key generation failed: {key_error}", "Jamf", System.TimeSpan.Zero));
            return;
        }

        // Envelope to the RA encryption cert (split-RA / PQ safe), poll against the CA signing-cert subject.
        selection = ScepWright.Core.Recipients.RecipientSelector.Select(ca_bundle);
        recipient = selection.EncryptionCertificate ?? selection.SigningCertificate ?? ca_bundle[0];
        issuer_dn = (selection.SigningCertificate ?? ca_bundle[0]).Subject;

        request = new EnrollRequest {
            Subject = "CN=jamf-probe",
            Key = key,
            CaCertificate = recipient,
            ChallengePassword = challenge,
        };

        result = ScepWright.Core.Testing.JamfSimulator.Run(client, request, issuer_dn, System.TimeSpan.FromMilliseconds(ms), System.TimeSpan.FromMilliseconds(500));

        if (!result.TimedOut) {
            output.WriteLine($"jamf timing: completed in {result.Elapsed.TotalMilliseconds:0}ms ({result.PollCount} polls, final status {result.FinalStatus})");
            report.Results.Add(new ScepWright.Core.Testing.CheckResult("jamf timing", ScepWright.Core.Testing.CheckOutcome.Passed,
                FailInfo.None, FailInfo.None, result.FinalStatus, $"jamf poll completed in {result.Elapsed.TotalMilliseconds:0}ms ({result.PollCount} polls)", "Jamf", result.Elapsed));
        } else {
            output.WriteLine($"jamf timing: exceeded {ms}ms (final status {result.FinalStatus})");
            report.Results.Add(new ScepWright.Core.Testing.CheckResult("jamf timing", ScepWright.Core.Testing.CheckOutcome.Failed,
                FailInfo.None, FailInfo.None, result.FinalStatus, $"jamf poll exceeded {ms}ms", "Jamf", result.Elapsed));
        }
    }

    // Rejects bad --report-format values BEFORE the suite runs (so a typo fails closed with exit 2,
    // not after issuing real certs and then silently writing no report).
    private static bool ValidateReportFormats(string[] args, TextWriter output) {
        foreach (string format in OptAll(args, "--report-format")) {
            switch (format.ToLowerInvariant()) {
                case "junit":
                case "trx":
                case "json":
                case "md":
                    break;
                default:
                    output.WriteLine($"unknown report format '{format}' (expected junit|trx|json|md)");
                    return false;
            }
        }
        return true;
    }

    private static System.Collections.Generic.List<string> OptAll(string[] args, string name) {
        System.Collections.Generic.List<string> values;
        int i;

        values = new System.Collections.Generic.List<string>();
        for (i = 0; i < args.Length - 1; i++) {
            if (args[i] == name) { values.Add(args[i + 1]); }
        }
        return values;
    }

    private static void WriteReports(ScepWright.Core.Testing.TestReport report, System.Collections.Generic.List<string> formats, string data_root, string server_id, TextWriter output, bool fail_on_findings) {
        string runs_dir;
        string stamp;

        if (formats.Count == 0) { return; }
        runs_dir = Path.Combine(data_root, "runs");
        Directory.CreateDirectory(runs_dir);
        stamp = System.DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");

        foreach (string format in formats) {
            string content;
            string ext;
            string report_path;

            switch (format.ToLowerInvariant()) {
                case "junit": content = ScepWright.Core.Reporting.JUnitReport.Emit(report, fail_on_findings); ext = "junit.xml"; break;
                case "trx": content = ScepWright.Core.Reporting.TrxReport.Emit(report); ext = "trx"; break;
                case "json": content = ScepWright.Core.Reporting.JsonReport.Emit(report); ext = "json"; break;
                case "md": content = ScepWright.Core.Reporting.MarkdownReport.Emit(report); ext = "md"; break;
                default: output.WriteLine($"unknown report format: {format}"); continue;
            }

            report_path = Path.Combine(runs_dir, $"{stamp}-{server_id}-{report.Mode}.{ext}");
            File.WriteAllText(report_path, content);
            output.WriteLine($"wrote {format} report: {report_path}");
        }
    }

    // -------------------------------------------------------------------------
    // run (scenario / playlist)
    // -------------------------------------------------------------------------

    private static int RunScenario(string[] args, string data_root, TextWriter output) {
        string path;
        string server_id;
        string json;
        ScepWright.Core.Testing.ScenarioFile scenario;
        string parse_error;
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;
        ScepWright.Core.Testing.TestReport report;
        System.Collections.Generic.List<string> formats;

        if (args.Length < 3) { output.WriteLine("usage: run <scenario.json> <server> [--report-format ...] [--fail-on-findings]"); return 2; }
        if (!RejectUnknownFlags(args, output, new[] { "--report-format" }, new[] { "--fail-on-findings" })) { return 2; }
        if (!ValidateReportFormats(args, output)) { return 2; }
        path = args[1];
        server_id = args[2];
        if (!File.Exists(path)) { output.WriteLine($"scenario not found: {path}"); return 2; }
        json = File.ReadAllText(path);
        if (!ScepWright.Core.Testing.ScenarioRunner.Parse(json, out scenario, out parse_error)) { output.WriteLine($"bad scenario: {parse_error}"); return 2; }
        if (!BuildClient(args, server_id, data_root, output, out client, out stored)) { return 2; }

        ca = client.GetCaCert();
        if (!ca.IsOk) { output.WriteLine($"GetCACert failed: {ca.Status} {ca.Error}"); return 1; }
        report = ScepWright.Core.Testing.ScenarioRunner.Run(client, scenario, ca.Value[0]);

        StampReport(report, stored, client);
        output.Write(ScepWright.Core.Reporting.ConsoleSummary.Emit(report));
        formats = OptAll(args, "--report-format");
        WriteReports(report, formats, data_root, server_id, output, HasFlag(args, "--fail-on-findings"));
        return TestExitCode(report, args);
    }

    // -------------------------------------------------------------------------
    // Challenge-source resolution (explicit > simulator > ndes)
    // -------------------------------------------------------------------------

    private static bool ResolveChallenge(string[] args, string server_url, System.Net.Http.HttpClient http, out string? challenge, out string error) {
        string? explicit_pw;
        string? simulator;
        ScepWright.Core.Challenge.IChallengeSource source;
        string resolved;

        challenge = null;
        error = string.Empty;

        explicit_pw = Opt(args, "--challenge");
        if (explicit_pw != null) { challenge = explicit_pw; return true; }

        simulator = Opt(args, "--simulator");
        if (simulator != null) {
            source = new ScepWright.Core.Challenge.SimulatorChallengeSource(http, simulator);
            if (!source.TryGet(out resolved, out error)) { return false; }
            challenge = resolved;
            return true;
        }

        if (HasFlag(args, "--ndes")) {
            string admin_url;
            string user;
            string password;

            admin_url = ScepWright.Core.Challenge.NdesAdminUrl.Derive(server_url, Opt(args, "--ndes-admin-url"));
            user = Opt(args, "--ndes-user") ?? string.Empty;
            password = Opt(args, "--ndes-password") ?? string.Empty;
            source = new ScepWright.Core.Challenge.NdesChallengeSource(http, admin_url, user, password);
            if (!source.TryGet(out resolved, out error)) { return false; }
            challenge = resolved;
            return true;
        }

        return true; // no challenge source; null is fine
    }

    private static bool IsKnownVariant(string text) {
        switch (text) {
            case "proper":
            case "reenroll-same-subject":
            case "pkcsreq-old-cert":
            case "same-key":
            case "expired":
                return true;
            default:
                return false;
        }
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
        if (args.Length < 2 || args[1] == "list") {
            return RunCertsList(data_root, args.Length >= 3 ? args[2] : null, output);
        }

        switch (args[1]) {
            case "show":
                return RunCertsShow(args, data_root, output);
            case "export":
                return RunCertsExport(args, data_root, output);
            default:
                output.WriteLine($"unknown certs sub-command '{args[1]}'");
                return WriteUsage(output);
        }
    }

    private static int RunCertsList(string data_root, string? server_id, TextWriter output) {
        string servers_root;
        System.Collections.Generic.List<string[]> rows;

        servers_root = Path.Combine(data_root, "servers");
        rows = new System.Collections.Generic.List<string[]>();

        if (Directory.Exists(servers_root)) {
            if (!string.IsNullOrEmpty(server_id)) {
                CollectCertRows(servers_root, server_id, rows);
            } else {
                string[] server_dirs;
                server_dirs = Directory.GetDirectories(servers_root);
                foreach (string server_dir in server_dirs) {
                    CollectCertRows(servers_root, Path.GetFileName(server_dir), rows);
                }
            }
        }

        if (rows.Count == 0) {
            output.WriteLine($"no certificates stored under {Path.GetFullPath(servers_root)}");
            return 0;
        }

        PrintTable(output, new[] { "SUBJECT", "KEY-SPEC", "EXPIRES", "STATUS", "ID" }, rows);
        return 0;
    }

    private static void CollectCertRows(string servers_root, string server_id, System.Collections.Generic.List<string[]> rows) {
        string certs_dir;
        string[] cert_dirs;
        System.Collections.Generic.HashSet<string> superseded;

        certs_dir = Path.Combine(servers_root, server_id, "certificates");
        if (!Directory.Exists(certs_dir)) {
            return;
        }

        cert_dirs = Directory.GetDirectories(certs_dir);

        // A cert is "superseded" when a newer cert was renewed FROM it — so the current one in a renewal
        // lineage is distinguishable (Bob's "which of these two same-subject certs is live?").
        superseded = new System.Collections.Generic.HashSet<string>();
        foreach (string cert_dir in cert_dirs) {
            CertStore.CertRecord? record;
            record = ReadRecord(Path.Combine(cert_dir, "metadata.json"));
            if (!string.IsNullOrEmpty(record?.RenewedFrom)) { superseded.Add(record!.RenewedFrom!); }
        }

        foreach (string cert_dir in cert_dirs) {
            CertStore.CertRecord? record;
            string thumbprint;
            string status;

            record = ReadRecord(Path.Combine(cert_dir, "metadata.json"));
            thumbprint = Path.GetFileName(cert_dir);
            status = superseded.Contains(thumbprint) ? "superseded" : (string.IsNullOrEmpty(record?.Status) ? "-" : record!.Status);
            rows.Add(new[] {
                record?.Subject ?? "(unknown)",
                string.IsNullOrEmpty(record?.KeySpec) ? "-" : record!.KeySpec!,
                record is null ? "-" : record.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"),
                status,
                $"{server_id}/{thumbprint}",
            });
        }
    }

    private static int RunCertsShow(string[] args, string data_root, TextWriter output) {
        CertStore store;
        string server_id;
        string cert_id;
        string resolve_error;
        CertStore.CertRecord? record;

        if (args.Length < 3) { output.WriteLine("usage: certs show <certId>"); return 2; }
        if (!RejectUnknownFlags(args, output, System.Array.Empty<string>(), System.Array.Empty<string>())) { return 2; }

        store = new CertStore(data_root);
        if (!ResolveCertId(store, args[2], out server_id, out cert_id, out resolve_error)) { output.WriteLine(resolve_error); return 2; }

        record = ReadRecord(Path.Combine(data_root, "servers", server_id, "certificates", cert_id, "metadata.json"));
        if (record is null) { output.WriteLine($"no stored certificate '{args[2]}'"); return 2; }

        output.WriteLine($"Id:            {server_id}/{cert_id}");
        output.WriteLine($"StoredIn:      {Path.GetFullPath(Path.Combine(data_root, "servers", server_id, "certificates", cert_id))}");
        output.WriteLine($"Subject:       {record.Subject}");
        output.WriteLine($"Serial:        {record.Serial}");
        output.WriteLine($"NotBefore:     {record.NotBefore.ToUniversalTime():u}");
        output.WriteLine($"NotAfter:      {record.NotAfter.ToUniversalTime():u}{(record.NotAfter.ToUniversalTime() < System.DateTime.UtcNow ? "  (EXPIRED)" : string.Empty)}");
        output.WriteLine($"KeySpec:       {(string.IsNullOrEmpty(record.KeySpec) ? "(unknown)" : record.KeySpec)}");
        output.WriteLine($"Status:        {record.Status}");
        output.WriteLine($"KeyAtRest:     {(store.IsKeyEncrypted(server_id, cert_id) ? "encrypted (PBES2/AES-256)" : "plaintext")}");
        if (!string.IsNullOrEmpty(record.RenewedFrom)) { output.WriteLine($"RenewedFrom:   {record.RenewedFrom}"); }
        if (!string.IsNullOrEmpty(record.TransactionId)) { output.WriteLine($"TransactionId: {record.TransactionId}"); }
        return 0;
    }

    private static int RunCertsExport(string[] args, string data_root, TextWriter output) {
        CertStore store;
        string server_id;
        string cert_id;
        string resolve_error;
        string format;
        string? out_path;
        bool is_encrypted;
        string? passphrase;
        IScepCrypto crypto;
        string crypto_error;
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        IScepKey key;
        CertStore.CertRecord record;
        string load_error;
        string base_name;
        bool legacy;
        byte[] key_der;
        string key_error;
        string cert_path;
        string key_path;
        bool encrypted_out;
        string pem_base;

        if (args.Length < 3) { output.WriteLine("usage: certs export <certId> [--out <path>] [--format pfx|pem] [--legacy] [--key-pass <pw>]"); return 2; }
        if (!RejectUnknownFlags(args, output, new[] { "--out", "--format", "--key-pass" }, new[] { "--legacy" })) { return 2; }

        legacy = HasFlag(args, "--legacy");
        format = (Opt(args, "--format") ?? "pfx").ToLowerInvariant();
        if (format != "pfx" && format != "pem") { output.WriteLine($"unknown --format '{format}' (expected pfx or pem)"); return 2; }
        out_path = Opt(args, "--out");
        if (out_path != null) {
            string out_dir;
            out_dir = Path.GetDirectoryName(Path.GetFullPath(out_path)) ?? string.Empty;
            if (!string.IsNullOrEmpty(out_dir) && !Directory.Exists(out_dir)) {
                output.WriteLine($"output directory does not exist: {out_dir}  (create it, or choose a different --out path)");
                return 2;
            }
        }

        store = new CertStore(data_root);
        if (!ResolveCertId(store, args[2], out server_id, out cert_id, out resolve_error)) { output.WriteLine(resolve_error); return 2; }

        is_encrypted = store.IsKeyEncrypted(server_id, cert_id);

        // A PFX is always password-protected; an encrypted stored key also needs its passphrase to read.
        passphrase = (format == "pfx" || is_encrypted)
            ? PassphrasePrompt.Resolve(Opt(args, "--key-pass"), "Key passphrase")
            : Opt(args, "--key-pass");
        if (is_encrypted && string.IsNullOrEmpty(passphrase)) {
            output.WriteLine($"certificate '{args[2]}' has an encrypted key; a passphrase is required (--key-pass, $SCEPWRIGHT_KEY_PASS, or prompt)");
            return 2;
        }

        if (ScepCrypto.Load(ResolveProviderPath(args, data_root), out crypto, out crypto_error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return 1;
        }

        if (!store.Load(server_id, cert_id, crypto, out cert, out key, out record, out load_error, is_encrypted ? passphrase : null)) {
            output.WriteLine(load_error);
            return 1;
        }

        base_name = SanitizeFileName(cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false));
        if (string.IsNullOrEmpty(base_name)) { base_name = cert_id; }

        if (format == "pfx") {
            byte[] p12;
            string pfx_error;
            string pfx_path;

            if (string.IsNullOrEmpty(passphrase)) {
                output.WriteLine("a PFX must be password-protected; supply a password (--key-pass, $SCEPWRIGHT_KEY_PASS, or prompt)");
                return 2;
            }
            if (!crypto.ExportPkcs12(key, cert, System.Array.Empty<System.Security.Cryptography.X509Certificates.X509Certificate2>(), passphrase!, legacy, out p12, out pfx_error)) {
                output.WriteLine($"PFX export failed: {pfx_error}");
                return 1;
            }
            pfx_path = out_path ?? $"{base_name}.p12";
            File.WriteAllBytes(pfx_path, p12);
            output.WriteLine($"wrote PKCS#12: {Path.GetFullPath(pfx_path)}");
            output.WriteLine("  protected with the supplied password (--key-pass); the same password unlocks the .pfx on import");
            output.WriteLine(legacy
                ? "  (legacy PKCS#12: SHA-1/RC2/3DES bags for old importers)"
                : "  (modern PKCS#12: PBES2/AES-256 bags; use --legacy for very old importers)");
            return 0;
        }

        // PEM bundle: cert + key, key encrypted when a passphrase is available.
        encrypted_out = !string.IsNullOrEmpty(passphrase);
        if (encrypted_out) {
            if (!crypto.ExportPrivateKeyPkcs8Encrypted(key, passphrase!, out key_der, out key_error)) { output.WriteLine($"key export failed: {key_error}"); return 1; }
        } else {
            if (!crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) { output.WriteLine($"key export failed: {key_error}"); return 1; }
        }

        // --out is a base/stem for the pair; strip any extension so `--out dev.pem` yields
        // dev-cert.pem / dev-key.pem (not dev.pem-cert.pem).
        pem_base = out_path != null
            ? Path.Combine(Path.GetDirectoryName(out_path) ?? string.Empty, Path.GetFileNameWithoutExtension(out_path))
            : base_name;
        cert_path = $"{pem_base}-cert.pem";
        key_path = $"{pem_base}-key.pem";
        File.WriteAllText(cert_path, cert.ExportCertificatePem());
        File.WriteAllText(key_path, PemArmor(encrypted_out ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY", key_der));
        output.WriteLine($"wrote certificate: {Path.GetFullPath(cert_path)}");
        output.WriteLine($"wrote private key: {Path.GetFullPath(key_path)}{(encrypted_out ? string.Empty : "   (UNENCRYPTED — protect this file)")}");
        return 0;
    }

    private static bool ResolveCertId(CertStore store, string raw, out string server_id, out string cert_id, out string error) {
        int slash;
        string? found;

        server_id = string.Empty;
        cert_id = string.Empty;
        error = string.Empty;

        slash = raw.IndexOf('/');
        if (slash >= 0) {
            server_id = raw.Substring(0, slash);
            cert_id = raw.Substring(slash + 1);
            return true;
        }

        found = store.FindServerForCert(raw);
        if (found is null) { error = $"no stored certificate '{raw}'"; return false; }
        server_id = found;
        cert_id = raw;
        return true;
    }

    private static CertStore.CertRecord? ReadRecord(string metadata_path) {
        if (!File.Exists(metadata_path)) { return null; }
        try {
            return System.Text.Json.JsonSerializer.Deserialize<CertStore.CertRecord>(File.ReadAllText(metadata_path));
        } catch {
            return null;
        }
    }

    private static string PemArmor(string label, byte[] der) {
        return $"-----BEGIN {label}-----\n{System.Convert.ToBase64String(der, System.Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----\n";
    }

    private static string SanitizeFileName(string text) {
        System.Text.StringBuilder builder;

        if (string.IsNullOrEmpty(text)) { return string.Empty; }
        builder = new System.Text.StringBuilder(text.Length);
        foreach (char c in text) {
            builder.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_');
        }
        return builder.ToString();
    }

    private static void PrintTable(TextWriter output, string[] headers, System.Collections.Generic.List<string[]> rows) {
        int[] widths;
        int i;
        System.Text.StringBuilder line;

        widths = new int[headers.Length];
        for (i = 0; i < headers.Length; i++) { widths[i] = headers[i].Length; }
        foreach (string[] row in rows) {
            for (i = 0; i < headers.Length && i < row.Length; i++) {
                if (row[i].Length > widths[i]) { widths[i] = row[i].Length; }
            }
        }

        line = new System.Text.StringBuilder();
        for (i = 0; i < headers.Length; i++) {
            if (i > 0) { line.Append("  "); }
            line.Append(i == headers.Length - 1 ? headers[i] : headers[i].PadRight(widths[i]));
        }
        output.WriteLine(line.ToString());

        foreach (string[] row in rows) {
            line.Clear();
            for (i = 0; i < headers.Length; i++) {
                string cell;
                cell = i < row.Length ? row[i] : string.Empty;
                if (i > 0) { line.Append("  "); }
                line.Append(i == headers.Length - 1 ? cell : cell.PadRight(widths[i]));
            }
            output.WriteLine(line.ToString());
        }
    }

    // -------------------------------------------------------------------------
    // config set / show
    // -------------------------------------------------------------------------

    private static int RunConfig(string[] args, string data_root, TextWriter output) {
        ClientConfig config;

        if (args.Length >= 4 && args[1] == "set") {
            string key;
            string value;
            int bits;
            int seconds;
            KeySpec parsed_spec;
            string spec_error;

            config = ClientConfig.Load(data_root);
            key = args[2];
            value = args[3];

            switch (key) {
                case "crypto-provider": config.CryptoProviderPath = value; break;
                case "key-spec":
                    if (!KeySpec.Parse(value, out parsed_spec, out spec_error)) {
                        output.WriteLine($"invalid key-spec '{value}': {spec_error}");
                        return 2;
                    }
                    config.KeySpec = value;
                    break;
                case "min-rsa-bits":
                    if (!int.TryParse(value, out bits) || bits <= 0) {
                        output.WriteLine($"min-rsa-bits must be a positive integer (got '{value}')");
                        return 2;
                    }
                    config.MinRsaKeyBits = bits;
                    break;
                case "timeout-seconds":
                    if (!int.TryParse(value, out seconds) || seconds <= 0) {
                        output.WriteLine($"timeout-seconds must be a positive integer (got '{value}')");
                        return 2;
                    }
                    config.TimeoutSeconds = seconds;
                    break;
                default: output.WriteLine($"unknown config key '{key}'"); return 2;
            }

            config.Save(data_root);
            output.WriteLine($"set {key} = {value}");
            return 0;
        }

        if (args.Length < 2 || args[1] != "show") {
            return WriteUsage(output);
        }

        config = ClientConfig.Load(data_root);
        output.WriteLine($"crypto-provider:  {config.CryptoProviderPath ?? "(default)"}");
        output.WriteLine($"key-spec:         {config.KeySpec}");
        output.WriteLine($"min-rsa-bits:     {config.MinRsaKeyBits}");
        output.WriteLine($"timeout-seconds:  {config.TimeoutSeconds}");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Usage
    // -------------------------------------------------------------------------

    /// <summary>Builds the help text for the certificate-management ("use it") commands.</summary>
    /// <param name="run_as">The invocation name to show in the header, or <c>null</c> for the default.</param>
    public static string HelpUse(string? run_as = null) {
        string header;

        header = run_as == null
            ? "Use it — get and manage real certificates:"
            : $"Use it — get and manage real certificates   (run as: {run_as} <command>)";

        return string.Join('\n', new[] {
            header,
            "  servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get|post]",
            "  servers list",
            "  servers show <id>",
            "  get <serverId> --subject \"CN=x\" [--challenge <pw>] [--key-spec <rsa:2048|ec:p256|ml-dsa:65|slh-dsa:192f>] [--alt-key-spec ml-dsa:65] [--digest SHA-256] [--cipher AES-128-CBC] [--sid <s>] [-v]",
            "  enroll <serverId> --subject \"CN=x\" [--challenge <pw> | --simulator <url> | --ndes --ndes-user <u> --ndes-password <p>] [--key-spec <rsa:2048|ec:p256|ml-dsa:65|slh-dsa:192f>] [--digest SHA-256] [--cipher AES-128-CBC] [--encrypt-keys --key-pass <pw>]",
            "  renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--challenge <pw>] [--encrypt-keys --key-pass <pw>]   (certId: the 'serverId/thumbprint' from `certs list`, or a bare thumbprint)",
            "  certs list [serverId]            (table: subject, key-spec, expiry, status, id)",
            "  certs show <certId>              (full metadata for one cert)",
            "  certs export <certId> [--out <path>] [--format pfx|pem] [--legacy] [--key-pass <pw>]   (deployable PKCS#12 (default, PBES2/AES-256) or PEM bundle; --legacy = old SHA-1/RC2/3DES PFX)",
            "  config show",
            "  config set <key> <value>   (keys: crypto-provider, key-spec, min-rsa-bits, timeout-seconds)",
            "  crypto info",
            "  crypto list",
            "  (key types: rsa, ec, ml-dsa, slh-dsa — see `crypto info` for the loaded provider's full list)",
            "  (passphrases: --key-pass <pw>, else $SCEPWRIGHT_KEY_PASS, else an interactive hidden prompt; encrypted keys use PBES2/AES-256)",
            "  (--alt-key-spec is an EXPERIMENTAL non-conformant probe — not a usable second credential; the alt key is not retained)",
        });
    }

    /// <summary>Builds the help text for the compliance-testing ("test with it") commands.</summary>
    /// <param name="run_as">The invocation name to show in the header, or <c>null</c> for the default.</param>
    public static string HelpTest(string? run_as = null) {
        string header;

        header = run_as == null
            ? "Test with it — exercise a SCEP server for RFC 8894 compliance:"
            : $"Test with it — exercise a SCEP server for RFC 8894 compliance   (run as: {run_as} <command>)";

        return string.Join('\n', new[] {
            header,
            "  diagnose <serverId> [-v]         (read-only health check: caps, CA/RA cert details, recipient verdict; -v traces the request URLs)",
            "  getcacaps <serverId>",
            "  getcacert <serverId> [-v]        (-v shows full CA/RA cert details)",
            "  getnextcacert <serverId>",
            "  poll <serverId> --issuer <dn> --subject <dn> --txn <id> [--key-pass <pw>]   (completes a PENDING enroll: stores the issued cert+key in `certs list`)",
            "  getcert <serverId> --issuer <dn> --serial <hex>",
            "  getcrl <serverId> --issuer <dn> --serial <hex>",
            "  servers suggest <id>",
            "  full|lifecycle|probe <serverId> [--dry-run] [--report-format junit|trx|json|md] [--jamf-max-wait <ms>] [--challenge <pw> | --simulator <url> | --ndes …]   (also: test <verb> <serverId>)",
            "      (--dry-run = read-only checks only; issues no certificates)",
            "  run <scenario.json> <serverId> [--report-format junit|trx|json|md]",
        });
    }

    private static int WriteUsage(TextWriter output) {
        output.WriteLine("usage: scepclient [--data-dir <path>] <command> [options]");
        output.WriteLine("       (storage root: --data-dir <path>, or $SCEPWRIGHT_HOME, else ~/.scepwright)");
        output.WriteLine();
        output.WriteLine(HelpUse());
        output.WriteLine();
        output.WriteLine(HelpTest());
        return 2;
    }

    // -------------------------------------------------------------------------
    // Option helpers
    // -------------------------------------------------------------------------

    internal static string? ResolveProviderPath(string[] args, string data_root) {
        string? flag;
        ClientConfig config;

        flag = Opt(args, "--crypto-provider");
        if (!string.IsNullOrWhiteSpace(flag)) { return flag; }

        config = ClientConfig.Load(data_root);
        return config.CryptoProviderPath;
    }

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

    // Flags accepted by every command (the dispatcher and provider plumbing consume these
    // regardless of the noun). value_flags take a following value; bool_flags stand alone.
    private static readonly string[] CommonValueFlags = { "--data-dir", "--crypto-provider" };
    private static readonly string[] CommonBoolFlags = { "-h", "--help" };

    // Rejects any token that looks like a flag (starts with '-') but is not in the command's
    // allowed set. Values that follow a known value-flag are skipped so they are never mistaken
    // for flags. Returns false (and prints the offending flag) on the first unknown flag.
    private static bool RejectUnknownFlags(string[] args, TextWriter output, string[] value_flags, string[] bool_flags) {
        HashSet<string> values;
        HashSet<string> bools;
        int i;

        values = new HashSet<string>(value_flags);
        values.UnionWith(CommonValueFlags);
        bools = new HashSet<string>(bool_flags);
        bools.UnionWith(CommonBoolFlags);

        for (i = 0; i < args.Length; i++) {
            string token;

            token = args[i];
            if (token.Length == 0 || token[0] != '-') { continue; }   // positional argument
            if (values.Contains(token)) { i++; continue; }            // skip the flag's value
            if (bools.Contains(token)) { continue; }

            output.WriteLine($"unknown flag '{token}'");
            return false;
        }
        return true;
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
