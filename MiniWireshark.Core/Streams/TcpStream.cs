namespace MiniWireshark.Core.Streams;

public readonly record struct TcpEndpoint(string Ip, ushort Port)
{
    public override string ToString() => $"{Ip}:{Port}";
}

public sealed class TcpStreamSegment
{
    public required int PacketNumber { get; init; }
    public required DateTime Timestamp { get; init; }
    public required bool FromEndpointA { get; init; }
    public required uint SequenceNumber { get; init; }
    public required byte[] Payload { get; init; }
}

public sealed class TcpStream
{
    public required int StreamIndex { get; init; }
    public required TcpEndpoint EndpointA { get; init; }
    public required TcpEndpoint EndpointB { get; init; }
    public List<TcpStreamSegment> Segments { get; } = new();

}