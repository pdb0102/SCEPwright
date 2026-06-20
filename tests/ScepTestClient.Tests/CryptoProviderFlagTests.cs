using System.IO;
using ScepTestClient.Cli;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class CryptoProviderFlagTests {
    [Fact]
    public void Config_set_persists_crypto_provider() {
        string root;
        StringWriter output;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        output = new StringWriter();
        Assert.Equal(0, CommandRouter.Run(new[] { "config", "set", "crypto-provider", "/tmp/p.dll" }, root, output));

        output = new StringWriter();
        Assert.Equal(0, CommandRouter.Run(new[] { "config", "show" }, root, output));
        Assert.Contains("/tmp/p.dll", output.ToString());
    }

    [Fact]
    public void Bogus_provider_path_errors_cleanly() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "list", "--crypto-provider", "/nope.dll" }, Path.GetTempPath(), output);
        Assert.NotEqual(0, code);
        Assert.Contains("not found", output.ToString());
    }
}
