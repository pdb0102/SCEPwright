using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Cli;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class CliScenarioSuggestTests {
    [Fact]
    public async Task ServersSuggest_PrintsEnrollCommands() {
        FakeScepServer server;
        string root;
        StringWriter output;
        int code;

        server = await FakeScepServer.StartAsync();
        try {
            root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            AddServer(root, server.ScepUrl.ToString());

            output = new StringWriter();
            code = CommandRouter.Run(new[] { "servers", "suggest", "testhost" }, root, output);

            Assert.Equal(0, code);
            Assert.Contains("sceptest enroll testhost", output.ToString());
            Assert.Contains("--digest SHA-256", output.ToString());
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task RunScenario_AggregatesAndExits() {
        FakeScepServer server;
        string root;
        string scenario_path;
        StringWriter output;
        int code;

        server = await FakeScepServer.StartAsync();
        try {
            root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            AddServer(root, server.ScepUrl.ToString());

            scenario_path = Path.Combine(root, "s.json");
            File.WriteAllText(scenario_path, "{ \"name\": \"s\", \"steps\": [ { \"name\": \"caps\", \"run\": \"getcacaps\", \"expect\": \"pass\" } ] }");

            output = new StringWriter();
            code = CommandRouter.Run(new[] { "run", scenario_path, "testhost" }, root, output);

            Assert.Equal(0, code);
            Assert.Contains("SCEP test run", output.ToString());
        } finally {
            await server.DisposeAsync();
        }
    }

    private static void AddServer(string root, string url) {
        StringWriter add_out;

        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", url, "--name", "testhost" }, root, add_out);
    }
}
