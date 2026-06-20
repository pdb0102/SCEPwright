using System.Collections.Generic;

namespace ScepTestClient.Core.Testing;

public sealed class ScenarioFile {
    public string Name { get; set; } = string.Empty;
    public List<ScenarioStep> Steps { get; set; } = new();
}

public sealed class ScenarioStep {
    public string Name { get; set; } = string.Empty;
    public string Run { get; set; } = string.Empty;
    public string? Server { get; set; }
    public Dictionary<string, string> Args { get; set; } = new();
    public string Expect { get; set; } = "pass";
}
