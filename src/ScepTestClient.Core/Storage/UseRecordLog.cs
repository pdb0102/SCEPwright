using System.IO;
using System.Text.Json;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Storage;

public sealed class UseRecordLog {
    private readonly string _root;

    public UseRecordLog(string root) {
        _root = root;
    }

    public void Append(string server_id, UseRecord record) {
        string server_dir;
        string history_file;
        string line;

        server_dir = Path.Combine(_root, "servers", server_id);
        Directory.CreateDirectory(server_dir);
        history_file = Path.Combine(server_dir, "history.jsonl");
        line = JsonSerializer.Serialize(record) + "\n";
        File.AppendAllText(history_file, line);
    }

    public void Append(string server_id, EnrollOutcome outcome) {
        UseRecord record;
        string? cert_id;

        cert_id = outcome.Certificate?.Thumbprint;
        record = new UseRecord {
            Operation = "Enroll",
            PkiStatus = outcome.PkiStatus.ToString(),
            TimingMs = (long)outcome.Elapsed.TotalMilliseconds,
            CertId = cert_id,
            FailInfo = outcome.FailInfo == ScepTestClient.CryptoApi.FailInfo.None
                ? null
                : outcome.FailInfo.ToString(),
            TransactionId = outcome.TransactionId,
        };
        Append(server_id, record);
    }
}
