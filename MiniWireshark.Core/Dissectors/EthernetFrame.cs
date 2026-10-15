using System.Net.NetworkInformation;

namespace MiniWireshark.Dissectors;

/// <summary>
/// Dissection d'une trame Ethernet II (14 octets d'en-tête minimum).
/// Format : [Dest MAC:6][Src MAC:6][EtherType:2][Payload...]
/// </summary>
public sealed class EthernetFrame
{
    public const int HeaderLength = 14;

    public PhysicalAddress DestinationMac { get; init; } = PhysicalAddress.None;
    public PhysicalAddress SourceMac { get; init; } = PhysicalAddress.None;
    public ushort EtherType { get; init; }
    public ReadOnlyMemory<byte> Payload { get; init; }

    public string EtherTypeName => EtherType switch
    {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "VLAN (802.1Q)",
        0x88A8 => "QinQ (802.1ad)",
        0x8809 => "Slow Protocols (LACP)",
        0x8863 => "PPPoE Discovery",
        0x8864 => "PPPoE Session",
        0x88CC => "LLDP",
        _ => $"0x{EtherType:X4}"
    };

    /// <summary>
    /// Parse les octets bruts capturés en trame Ethernet.
    /// Retourne null si la trame est trop courte pour être valide.
    /// </summary>
    public static EthernetFrame? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < HeaderLength)
            return null;

        var dstBytes = raw.Slice(0, 6).ToArray();
        var srcBytes = raw.Slice(6, 6).ToArray();
        ushort etherType = (ushort)((raw[12] << 8) | raw[13]);

        return new EthernetFrame
        {
            DestinationMac = new PhysicalAddress(dstBytes),
            SourceMac = new PhysicalAddress(srcBytes),
            EtherType = etherType,
            Payload = raw.Slice(HeaderLength).ToArray()
        };
    }
}
