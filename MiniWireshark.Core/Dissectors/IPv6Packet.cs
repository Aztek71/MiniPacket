using System.Net;

namespace MiniWireshark.Dissectors;

public sealed class IPv6Packet
{
    public const int HeaderLength = 40;
    
    public ushort PayloadLength { get; init; }
    public byte NextHeader { get; init; }
    public byte HopLimit { get; init; }
    public IPAddress SourceAddress { get; init; } = IPAddress.IPv6None;
    public IPAddress DestinationAddress { get; init; } = IPAddress.IPv6None;
    public ReadOnlyMemory<byte> Payload { get; init; }

    public string ProtocolName => NextHeader switch
    {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => $"Proto {NextHeader}"
    };

    public static IPv6Packet? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < HeaderLength)
            return null;

        int version = raw[0] >> 4;
        if (version != 6)
            return null;

        ushort payloadLength = (ushort)((raw[4] << 8) | raw[5]);
        byte nextHeader = raw[6];
        byte hopLimit = raw[7];

        var src = new IPAddress(raw.Slice(8, 16).ToArray());
        var dst = new IPAddress(raw.Slice(24, 16).ToArray());

        var payload = raw.Length > HeaderLength
            ? raw.Slice(HeaderLength).ToArray()
            : Array.Empty<byte>();

        return new IPv6Packet
        {
            PayloadLength = payloadLength,
            NextHeader = nextHeader,
            HopLimit = hopLimit,
            SourceAddress = src,
            DestinationAddress = dst,
            Payload = payload
        };
    }
}