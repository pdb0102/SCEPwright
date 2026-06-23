using System.IO;
using System.Threading.Tasks;
using ScepWright.Client;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class CliRouterPhase2Tests {
    // An unknown server is a usage/config error and must exit 2 everywhere — not 1, which
    // collides with a genuine check failure. Several commands used to exit 1.
    [Fact]
    public void Unknown_server_exits_2_consistently() {
        string root;

        root = Directory.CreateTempSubdirectory().FullName;
        Assert.Equal(2, CommandRouter.Run(new[] { "full", "ghost" }, root, new StringWriter()));
        Assert.Equal(2, CommandRouter.Run(new[] { "servers", "suggest", "ghost" }, root, new StringWriter()));
        Assert.Equal(2, CommandRouter.Run(new[] { "getcacert", "ghost" }, root, new StringWriter()));
    }

    // An empty `certs list` must name the storage root it searched, not just "none".
    [Fact]
    public void Certs_list_empty_shows_searched_path() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "certs", "list" }, root, outw);

        Assert.Equal(0, code);
        Assert.Contains("no certificates", outw.ToString());
        Assert.Contains(Path.Combine(root, "servers"), outw.ToString());
    }

    [Fact]
    public void Renew_without_args_returns_usage() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "renew" }, root, outw);
        Assert.Equal(2, code);
        Assert.Contains("usage: renew", outw.ToString());
    }

    [Fact]
    public void Getcert_requires_issuer_and_serial() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "h" }, root, outw);
        code = CommandRouter.Run(new[] { "getcert", "h" }, root, outw);
        Assert.Equal(2, code);
        Assert.Contains("required", outw.ToString());
    }

    [Fact]
    public async Task Get_then_renew_end_to_end() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        int add_code;
        int get_code;
        int renew_code;
        string listing;
        string cert_id;
        StringWriter list_out;
        StringWriter renew_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        add_code = CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        list_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "list", "fake" }, root, list_out);
        listing = list_out.ToString().Trim();
        cert_id = listing.Substring(listing.IndexOf('/') + 1);

        renew_out = new StringWriter();
        renew_code = CommandRouter.Run(new[] { "renew", cert_id }, root, renew_out);

        Assert.Equal(0, add_code);
        Assert.Equal(0, get_code);
        Assert.Equal(0, renew_code);
        Assert.Contains("renewed:", renew_out.ToString());
    }

    // A PFX export must state the .pfx is protected with the supplied password.
    [Fact]
    public async Task Certs_export_pfx_states_it_is_password_protected() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        StringWriter export_out;
        string text;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        export_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "export", $"fake/{cert_id}", "--format", "pfx", "--out", Path.Combine(root, "dev.p12"), "--key-pass", "s3cret" }, root, export_out);
        text = export_out.ToString();

        Assert.Contains("wrote PKCS#12", text);
        Assert.Contains("protected", text.ToLowerInvariant());
    }

    // `get`/`enroll` must expose a --dns flag so issued leaves can carry a SubjectAltName.
    [Fact]
    public async Task Get_with_dns_flag_issues_cert_with_subject_alt_name() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string cert_pem;
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        string san_text;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--dns", "host.example.com" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        cert_pem = Path.Combine(root, "servers", "fake", "certificates", cert_id, "cert.pem");
        cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(cert_pem));

        san_text = string.Empty;
        foreach (System.Security.Cryptography.X509Certificates.X509Extension ext in cert.Extensions) {
            if (ext.Oid?.Value == "2.5.29.17") { san_text = ext.Format(false); }
        }
        Assert.Contains("host.example.com", san_text);
    }

    // `servers add --help` used to register a bogus server named "help" (the URL positional was
    // consumed before --help could short-circuit). A flag-looking URL must be rejected, not stored.
    [Fact]
    public void Servers_add_rejects_flag_as_url() {
        string root;
        StringWriter outw;
        StringWriter listw;
        int rc;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        rc = CommandRouter.Run(new[] { "servers", "add", "--help" }, root, outw);

        Assert.NotEqual(0, rc);
        listw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "list" }, root, listw);
        Assert.Equal(string.Empty, listw.ToString().Trim());
    }

    // `servers list` ignored trailing flags entirely (it never received args), so a typo'd flag was
    // silently accepted. It must reject unknown flags like every other sub-command (exit 2).
    [Fact]
    public void Servers_list_rejects_unknown_flag() {
        string root;
        StringWriter outw;
        int rc;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        rc = CommandRouter.Run(new[] { "servers", "list", "--bogus" }, root, outw);

        Assert.Equal(2, rc);
        Assert.Contains("unknown flag", outw.ToString());
    }

    // `servers suggest` printed a warning but still exited 0 against a server with no encryption-capable
    // recipient (one that can't enroll), while `diagnose` correctly exits 1. suggest must reflect the
    // broken state in its exit code.
    [Fact]
    public async Task Servers_suggest_exits_nonzero_on_broken_server() {
        await using ScepServerApp server = await ScepServerApp.StartAsync(ScepCa.CreateSigningOnly());
        string root;
        StringWriter outw;
        int rc;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "broke" }, root, outw);
        rc = CommandRouter.Run(new[] { "servers", "suggest", "broke" }, root, outw);

        Assert.Equal(1, rc);
    }

    // A non-ASCII DNS SAN must be IDNA/punycode-encoded, not silently downcast to ASCII (which
    // substitutes '?' for each non-ASCII char: "munchen.de" with u-umlaut became "m?nchen.de"). RFC 5280
    // dNSName is an IA5String, so an internationalized name belongs in its A-label (punycode) form.
    [Fact]
    public async Task Get_with_non_ascii_dns_punycode_encodes_san() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string cert_pem;
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        string san_text;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--dns", "münchen.de" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        cert_pem = Path.Combine(root, "servers", "fake", "certificates", cert_id, "cert.pem");
        cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(cert_pem));

        san_text = string.Empty;
        foreach (System.Security.Cryptography.X509Certificates.X509Extension ext in cert.Extensions) {
            if (ext.Oid?.Value == "2.5.29.17") { san_text = ext.Format(false); }
        }
        Assert.Contains("xn--mnchen-3ya.de", san_text);
        Assert.DoesNotContain("?", san_text);
    }

    // An empty or whitespace --dns must be rejected (exit 2), not turned into an RFC-invalid
    // zero-length / blank dNSName ("DNS:" or "DNS:   "). The CA copies the request verbatim.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Get_with_blank_dns_is_rejected(string blank) {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        int rc;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        rc = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--dns", blank }, root, outw);

        Assert.Equal(2, rc);
        Assert.DoesNotContain(Directory.GetFiles(Path.Combine(root, "servers", "fake"), "cert.pem", SearchOption.AllDirectories), f => true);
    }

    // `renew` with a blank thumbprint ("fake/") used to leak an internal filesystem path via a raw
    // `fatal: Could not find file '…/cert.pem'`, and `renew ""` resolved to an arbitrary server. A blank
    // certId must be rejected up front with a clean "no stored certificate" message (exit 2), no path leak.
    [Theory]
    [InlineData("fake/")]
    [InlineData("")]
    public async Task Renew_with_blank_certid_is_rejected_cleanly(string cert_id) {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string text;
        int rc;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        // Issue a real cert so the server's certificates/ directory exists (the empty-segment leak trigger).
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        outw = new StringWriter();
        rc = CommandRouter.Run(new[] { "renew", cert_id }, root, outw);
        text = outw.ToString();

        Assert.Equal(2, rc);
        Assert.DoesNotContain("fatal:", text);
        Assert.DoesNotContain("cert.pem", text);
    }

    // `get`/`enroll` must expose a repeatable --eku flag so an issued leaf carries the requested
    // ExtendedKeyUsage (the CA honors the CSR's requested EKU, mirroring how it honors the SAN).
    [Fact]
    public async Task Get_with_eku_flag_issues_cert_with_extended_key_usage() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string cert_pem;
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        System.Collections.Generic.List<string> eku_oids;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--eku", "serverAuth", "--eku", "clientAuth" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        cert_pem = Path.Combine(root, "servers", "fake", "certificates", cert_id, "cert.pem");
        cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(cert_pem));

        eku_oids = new System.Collections.Generic.List<string>();
        foreach (System.Security.Cryptography.X509Certificates.X509Extension ext in cert.Extensions) {
            if (ext is System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension eku) {
                foreach (System.Security.Cryptography.Oid o in eku.EnhancedKeyUsages) {
                    if (o.Value != null) { eku_oids.Add(o.Value); }
                }
            }
        }

        Assert.Contains("1.3.6.1.5.5.7.3.1", eku_oids);   // serverAuth
        Assert.Contains("1.3.6.1.5.5.7.3.2", eku_oids);   // clientAuth
    }

    // Renew must echo the renewed key's at-rest encryption status, like enroll/get does.
    [Fact]
    public async Task Renew_echoes_key_at_rest_status() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        StringWriter renew_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        renew_out = new StringWriter();
        CommandRouter.Run(new[] { "renew", $"fake/{cert_id}" }, root, renew_out);

        Assert.Contains("renewed:", renew_out.ToString());
        Assert.Contains("key at rest", renew_out.ToString());
        Assert.Contains("UNENCRYPTED", renew_out.ToString());
    }

    [Fact]
    public async Task Get_with_encrypt_keys_writes_only_encrypted_key() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        int get_code;
        string listing;
        string cert_id;
        string cert_dir;
        StringWriter list_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--encrypt-keys", "--key-pass", "s3cret" }, root, outw);

        list_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "list", "fake" }, root, list_out);
        listing = list_out.ToString().Trim();
        cert_id = listing.Substring(listing.IndexOf('/') + 1);

        cert_dir = Path.Combine(root, "servers", "fake", "certificates", cert_id);
        Assert.Equal(0, get_code);
        Assert.True(File.Exists(Path.Combine(cert_dir, "key.pkcs8.enc")), "encrypted key should exist");
        Assert.False(File.Exists(Path.Combine(cert_dir, "key.pkcs8")), "plaintext key must NOT exist when --encrypt-keys is used");
    }

    [Fact]
    public void Encrypt_keys_without_key_pass_errors() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "h" }, root, outw);
        code = CommandRouter.Run(new[] { "get", "h", "--subject", "CN=x", "--encrypt-keys" }, root, outw);
        Assert.Equal(2, code);
    }

    [Fact]
    public async Task Renew_encrypted_cert_round_trips_and_stays_encrypted() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        int get_code;
        int renew_code;
        string cert_id;
        string certs_root;
        StringWriter renew_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=enc", "--challenge", "pw", "--encrypt-keys", "--key-pass", "hunter2" }, root, outw);

        cert_id = FirstCertId(root, "fake");
        renew_out = new StringWriter();
        renew_code = CommandRouter.Run(new[] { "renew", $"fake/{cert_id}", "--key-pass", "hunter2" }, root, renew_out);

        Assert.Equal(0, get_code);
        Assert.Equal(0, renew_code);
        Assert.Contains("renewed:", renew_out.ToString());

        // Every stored cert (original + renewed) keeps an encrypted key; none is silently downgraded.
        certs_root = Path.Combine(root, "servers", "fake", "certificates");
        Assert.True(Directory.GetDirectories(certs_root).Length >= 2);
        foreach (string dir in Directory.GetDirectories(certs_root)) {
            Assert.True(File.Exists(Path.Combine(dir, "key.pkcs8.enc")), "renewed key must stay encrypted");
            Assert.False(File.Exists(Path.Combine(dir, "key.pkcs8")), "no plaintext key may be written");
        }
    }

    [Fact]
    public async Task Renew_encrypted_cert_without_passphrase_errors() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        int renew_code;
        StringWriter renew_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=enc", "--challenge", "pw", "--encrypt-keys", "--key-pass", "hunter2" }, root, outw);
        cert_id = FirstCertId(root, "fake");

        renew_out = new StringWriter();
        renew_code = CommandRouter.Run(new[] { "renew", $"fake/{cert_id}" }, root, renew_out);

        Assert.Equal(2, renew_code);
        Assert.Contains("encrypted key", renew_out.ToString());
    }

    [Fact]
    public async Task Certs_list_shows_columns_and_show_displays_metadata() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        StringWriter list_out;
        StringWriter show_out;
        int show_code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);
        cert_id = FirstCertId(root, "fake");

        list_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "list" }, root, list_out);
        Assert.Contains("SUBJECT", list_out.ToString());
        Assert.Contains("KEY-SPEC", list_out.ToString());
        Assert.Contains("CN=poodle", list_out.ToString());

        show_out = new StringWriter();
        show_code = CommandRouter.Run(new[] { "certs", "show", $"fake/{cert_id}" }, root, show_out);
        Assert.Equal(0, show_code);
        Assert.Contains("Subject:", show_out.ToString());
        Assert.Contains("CN=poodle", show_out.ToString());
        Assert.Contains("KeyAtRest:", show_out.ToString());
    }

    [Fact]
    public async Task Certs_export_pfx_round_trips_with_private_key() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string pfx_path;
        int export_code;
        StringWriter export_out;
        System.Security.Cryptography.X509Certificates.X509Certificate2 loaded;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);
        cert_id = FirstCertId(root, "fake");
        pfx_path = Path.Combine(root, "dev.p12");

        export_out = new StringWriter();
        export_code = CommandRouter.Run(new[] { "certs", "export", $"fake/{cert_id}", "--out", pfx_path, "--key-pass", "secret" }, root, export_out);

        Assert.Equal(0, export_code);
        Assert.True(File.Exists(pfx_path));

        loaded = new System.Security.Cryptography.X509Certificates.X509Certificate2(File.ReadAllBytes(pfx_path), "secret");
        Assert.True(loaded.HasPrivateKey);
        Assert.Contains("CN=poodle", loaded.Subject);
    }

    // A plaintext private key from `get` must announce itself (security-aware non-experts land on `get`
    // first); `--encrypt-keys` suppresses the warning.
    [Fact]
    public async Task Get_warns_when_key_stored_unencrypted() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter plain;
        StringWriter enc;

        root = Directory.CreateTempSubdirectory().FullName;
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, new StringWriter());

        plain = new StringWriter();
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=plainkey", "--challenge", "pw" }, root, plain);
        Assert.Contains("UNENCRYPTED", plain.ToString());
        Assert.Contains("--encrypt-keys", plain.ToString());

        enc = new StringWriter();
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=enckey", "--challenge", "pw", "--encrypt-keys", "--key-pass", "s3cret" }, root, enc);
        Assert.DoesNotContain("UNENCRYPTED", enc.ToString());
    }

    // The modern PFX must carry a SHA-256 integrity MAC, not the BC-default SHA-1.
    [Fact]
    public async Task Certs_export_pfx_uses_sha256_mac() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string pfx_path;
        int export_code;
        Org.BouncyCastle.Asn1.Pkcs.Pfx pfx;
        System.Security.Cryptography.X509Certificates.X509Certificate2 loaded;
        StringWriter export_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=mactest", "--challenge", "pw" }, root, outw);
        cert_id = FirstCertId(root, "fake");
        pfx_path = Path.Combine(root, "mac.p12");

        export_out = new StringWriter();
        export_code = CommandRouter.Run(new[] { "certs", "export", $"fake/{cert_id}", "--out", pfx_path, "--key-pass", "secret" }, root, export_out);
        Assert.Equal(0, export_code);

        pfx = Org.BouncyCastle.Asn1.Pkcs.Pfx.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(File.ReadAllBytes(pfx_path)));
        Assert.NotNull(pfx.MacData);
        Assert.Equal(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdSha256.Id, pfx.MacData.Mac.DigestAlgorithm.Algorithm.Id);

        // The re-MAC must not break loading the key.
        loaded = new System.Security.Cryptography.X509Certificates.X509Certificate2(File.ReadAllBytes(pfx_path), "secret");
        Assert.True(loaded.HasPrivateKey);
    }

    [Fact]
    public async Task Certs_export_pem_writes_cert_and_key() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        string cert_id;
        string base_path;
        int export_code;
        StringWriter export_out;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);
        cert_id = FirstCertId(root, "fake");
        base_path = Path.Combine(root, "dev");

        export_out = new StringWriter();
        export_code = CommandRouter.Run(new[] { "certs", "export", $"fake/{cert_id}", "--format", "pem", "--out", base_path }, root, export_out);

        Assert.Equal(0, export_code);
        Assert.Contains("BEGIN CERTIFICATE", File.ReadAllText(base_path + "-cert.pem"));
        Assert.Contains("PRIVATE KEY", File.ReadAllText(base_path + "-key.pem"));
    }

    [Fact]
    public async Task Diagnose_reports_recipient_verdict() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        StringWriter diag;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);

        diag = new StringWriter();
        code = CommandRouter.Run(new[] { "diagnose", "fake" }, root, diag);

        Assert.Equal(0, code);
        Assert.Contains("GetCACaps", diag.ToString());
        Assert.Contains("KeyUsage", diag.ToString());
        Assert.Contains("VERDICT: OK", diag.ToString());
    }

    // `servers suggest` must be diagnosis-aware — against a signing-only CA (no encryption
    // recipient) every enroll command would fail, so it must warn and NOT emit enroll command lines.
    [Fact]
    public async Task Servers_suggest_warns_and_omits_enroll_lines_for_a_broken_signing_only_server() {
        await using ScepServerApp server = await ScepServerApp.StartAsync(ScepWright.Server.ScepCa.CreateSigningOnly());
        string root;
        StringWriter outw;
        StringWriter sugg;
        int code;
        string text;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);

        sugg = new StringWriter();
        code = CommandRouter.Run(new[] { "servers", "suggest", "fake" }, root, sugg);
        text = sugg.ToString();

        Assert.DoesNotContain("scepclient enroll", text);
        Assert.Contains("no encryption-capable recipient", text);
        Assert.Contains("diagnose", text);
    }

    // `diagnose` must accept -v so an operator can see the resolved request URL and trace lines;
    // it used to reject every flag, exiting 2 (usage error) on `diagnose <server> -v`.
    [Fact]
    public async Task Diagnose_accepts_verbose_flag() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter outw;
        StringWriter diag;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);

        diag = new StringWriter();
        code = CommandRouter.Run(new[] { "diagnose", "fake", "-v" }, root, diag);

        Assert.Equal(0, code);
        Assert.Contains("GetCACaps", diag.ToString());
    }

    private static string FirstCertId(string root, string server) {
        return Path.GetFileName(Directory.GetDirectories(Path.Combine(root, "servers", server, "certificates"))[0]);
    }
}
