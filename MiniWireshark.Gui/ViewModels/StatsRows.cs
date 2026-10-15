namespace MiniWireshark.Gui.ViewModels;

public sealed record ProtocolStatRow(string Protocol, int Count, double Percentage);

public sealed record TalkerRow(string Address, long PacketCount, string ByteCountDisplay);