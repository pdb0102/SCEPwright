using System;
using ScepTestClient.Core;

namespace ScepTestClient.Cli;

internal sealed class ConsoleTrace {
    private readonly int _verbosity;

    public ConsoleTrace(int verbosity) { _verbosity = verbosity; }

    public void Handle(ScepTraceEvent e) {
        if (e.Level == TraceLevel.Debug && _verbosity < 1) return;
        Console.Error.WriteLine($"[{e.Level}] {e.Phase}: {e.Message}");
    }
}
