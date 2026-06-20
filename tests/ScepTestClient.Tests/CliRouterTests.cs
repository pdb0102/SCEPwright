using System.IO;
using ScepTestClient.Cli;
using Xunit;

namespace ScepTestClient.Tests;

public class CliRouterTests {
    [Fact]
    public void Servers_add_then_list_round_trips() {
        string root;
        StringWriter outw;
        int add_code;
        int list_code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        add_code = CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "privpki" }, root, outw);
        list_code = CommandRouter.Run(new[] { "servers", "list" }, root, outw);

        Assert.Equal(0, add_code);
        Assert.Equal(0, list_code);
        Assert.Contains("privpki", outw.ToString());
        Assert.Contains("http://host/scep", outw.ToString());
    }

    [Fact]
    public void Unknown_command_returns_nonzero_and_usage() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        code = CommandRouter.Run(new[] { "frobnicate" }, root, outw);

        Assert.NotEqual(0, code);
        Assert.Contains("usage", outw.ToString().ToLowerInvariant());
    }
}
