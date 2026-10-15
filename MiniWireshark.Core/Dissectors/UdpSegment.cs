namespace MiniWireshark.Dissectors;

/// <summary>
/// Dissection d'un en-tête UDP (8 octets, taille fixe).
/// Format : [SrcPort:2][DstPort:2][Length:2][Checksum:2]
/// </summary>
public sealed class UdpSegment
{
    public const int HeaderLength = 8;

    public ushort SourcePort { get; init; }
    public ushort DestinationPort { get; init; }
    public ushort Length { get; init; } // en-tête + payload, en octets
    public int PayloadLength { get; init; }
    public ReadOnlyMemory<byte> Payload { get; init; }

    public static UdpSegment? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < HeaderLength)
            return null;

        ushort srcPort = (ushort)((raw[0] << 8) | raw[1]);
        ushort dstPort = (ushort)((raw[2] << 8) | raw[3]);
        ushort length = (ushort)((raw[4] << 8) | raw[5]);

        var payload = raw.Length > HeaderLength
            ? raw.Slice(HeaderLength).ToArray()
            : Array.Empty<byte>();

        return new UdpSegment
        {
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Length = length,
            PayloadLength = payload.Length,
            Payload = payload
        };
    }
}
