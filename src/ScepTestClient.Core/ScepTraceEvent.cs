namespace ScepTestClient.Core;

public enum TraceLevel { Debug, Info, Warning, Error, Opinion }

public sealed record ScepTraceEvent(TraceLevel Level, string Phase, string Message);
