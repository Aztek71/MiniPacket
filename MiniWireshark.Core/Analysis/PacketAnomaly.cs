namespace MiniWireshark.Core.Analysis;

public enum AnomalySeverity { Info, Warning, Error }

public sealed record PacketAnomaly(string Code, string Label, string Description, AnomalySeverity Severity);
