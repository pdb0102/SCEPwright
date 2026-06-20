namespace ScepTestClient.CryptoApi;

public enum NoteSeverity { Info, Warning }

public sealed record ConformanceNote(NoteSeverity Severity, string What, string Where, string RfcReference);
