using System.Net;

namespace MiniWireshark.Dissectors;

/// <summary>
/// Dissection d'un en-tête IPv4 (20 octets minimum, sans options).
/// Format simplifié :
/// [Ver/IHL:1][ToS:1][TotalLen:2][Id:2][Flags/Frag:2][TTL:1][Proto:1][Checksum:2][Src:4][Dst:4]
/// </summary>
public sealed class IPv4Packet
{
    public const int MinHeaderLength = 20;

    public int HeaderLength { get; init; } // en octets (IHL * 4)
    public ushort TotalLength { get; init; }
    public byte Ttl { get; init; }
    public byte Protocol { get; init; }
    public IPAddress SourceAddress { get; init; } = IPAddress.None;
    public IPAddress DestinationAddress { get; init; } = IPAddress.None;
    public ReadOnlyMemory<byte> Payload { get; init; }

    public string ProtocolName => Protocol switch
    {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => $"Proto {Protocol}"
    };

    public static IPv4Packet? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < MinHeaderLength)
            return null;

        byte versionAndIhl = raw[0];
        int version = versionAndIhl >> 4;
        if (version != 4)
            return null; // pas de l'IPv4 (pourrait être IPv6, etc.)

        int ihl = versionAndIhl & 0x0F; // nombre de mots de 32 bits
        int headerLen = ihl * 4;
        if (raw.Length < headerLen)
            return null;

        ushort totalLength = (ushort)((raw[2] << 8) | raw[3]);
        byte ttl = raw[8];
        byte protocol = raw[9];

        var srcAddr = new IPAddress(raw.Slice(12, 4).ToArray());
        var dstAddr = new IPAddress(raw.Slice(16, 4).ToArray());

        var payload = headerLen < raw.Length
            ? raw.Slice(headerLen).ToArray()
            : Array.Empty<byte>();

        return new IPv4Packet
        {
            HeaderLength = headerLen,
            TotalLength = totalLength,
            Ttl = ttl,
            Protocol = protocol,
            SourceAddress = srcAddr,
            DestinationAddress = dstAddr,
            Payload = payload
        };
    }
}
