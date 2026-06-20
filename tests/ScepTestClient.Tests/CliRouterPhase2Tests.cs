using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Cli;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class CliRouterPhase2Tests {
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
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        string root;
        StringWriter outw;
        int add_code;
        int get_code;
        int renew_code;
        string listing;
        string cert_id;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        add_code = CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        StringWriter list_out;
        list_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "list", "fake" }, root, list_out);
        listing = list_out.ToString().Trim();
        cert_id = listing.Substring(listing.IndexOf('/') + 1);

        StringWriter renew_out;
        renew_out = new StringWriter();
        renew_code = CommandRouter.Run(new[] { "renew", cert_id }, root, renew_out);

        Assert.Equal(0, add_code);
        Assert.Equal(0, get_code);
        Assert.Equal(0, renew_code);
        Assert.Contains("renewed:", renew_out.ToString());
    }

    [Fact]
    public async Task Get_with_encrypt_keys_writes_only_encrypted_key() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        string root;
        StringWriter outw;
        int get_code;
        string listing;
        string cert_id;
        string cert_dir;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw", "--encrypt-keys", "--key-pass", "s3cret" }, root, outw);

        StringWriter list_out;
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
}
