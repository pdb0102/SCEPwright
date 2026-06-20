using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Cli;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class CliTestCommandTests {
    [Fact]
    public async Task TestProbe_PrintsSummary_AndWritesJunit() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        string root;
        StringWriter output;
        int code;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        StringWriter add_out;
        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "testhost" }, root, add_out);

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "test", "probe", "testhost", "--report-format", "junit" }, root, output);

        Assert.Contains("SCEP test run", output.ToString());
        Assert.True(Directory.Exists(Path.Combine(root, "runs")));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "runs"), "*.junit.xml"));
        Assert.InRange(code, 0, 1);
    }

    [Fact]
    public void Test_UnknownVerb_Usage() {
        string root;
        StringWriter output;
        int code;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        StringWriter add_out;
        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "testhost" }, root, add_out);

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "test", "bogus", "testhost" }, root, output);
        Assert.Equal(2, code);
    }
}
