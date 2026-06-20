using System.IO;
using ScepTestClient.Core.Storage;
using Xunit;

namespace ScepTestClient.Tests;

public class StorageTests {
    [Fact]
    public void Redaction_is_stable_and_prefixed() {
        Assert.StartsWith("sha256:", Redaction.Hash("secret"));
        Assert.Equal(Redaction.Hash("secret"), Redaction.Hash("secret"));
        Assert.NotEqual(Redaction.Hash("a"), Redaction.Hash("b"));
    }

    [Fact]
    public void Explicit_dir_wins_over_breadcrumb() {
        string explicit_dir;
        string home;
        string resolved;

        explicit_dir = Directory.CreateTempSubdirectory().FullName;
        home = Directory.CreateTempSubdirectory().FullName;

        resolved = DataRoot.Resolve(explicit_dir, home);
        Assert.Equal(explicit_dir, resolved);
        Assert.False(File.Exists(Path.Combine(home, ".sceptest.json")));
    }

    [Fact]
    public void Default_writes_breadcrumb() {
        string home;
        string resolved;

        home = Directory.CreateTempSubdirectory().FullName;
        resolved = DataRoot.Resolve(null, home);

        Assert.Equal(Path.Combine(home, ".sceptestclient"), resolved);
        Assert.True(File.Exists(Path.Combine(home, ".sceptest.json")));
    }

    [Fact]
    public void Breadcrumb_is_read_when_present() {
        string home;
        string first;
        string second;

        home = Directory.CreateTempSubdirectory().FullName;
        first = DataRoot.Resolve(null, home);     // writes breadcrumb -> ~/.sceptestclient
        second = DataRoot.Resolve(null, home);    // should read the breadcrumb back
        Assert.Equal(first, second);
    }

    [Fact]
    public void Registry_round_trips() {
        string root;
        ServerRegistry registry;

        root = Directory.CreateTempSubdirectory().FullName;
        registry = new ServerRegistry(root);
        registry.Add(new StoredServer { Id = "privpki", Url = "http://host/scep/privpki", PreferPost = true });

        Assert.Single(registry.List());
        Assert.Equal("http://host/scep/privpki", registry.List()[0].Url);
        Assert.Equal("privpki", registry.Get("privpki")!.Id);
    }

    [Fact]
    public void Use_record_appends_jsonl_line() {
        string root;
        UseRecordLog log;
        string file;

        root = Directory.CreateTempSubdirectory().FullName;
        log = new UseRecordLog(root);
        log.Append("privpki", new UseRecord { Operation = "Enroll", PkiStatus = "Success", TimingMs = 12 });

        file = Path.Combine(root, "servers", "privpki", "history.jsonl");
        Assert.True(File.Exists(file));
        Assert.Single(File.ReadAllLines(file));
    }
}
