using MiniWireshark.Dissectors;

namespace MiniWireshark.Models;

/// <summary>
/// Represente un paquet capture, une fois entierement disseque.
/// C'est l'equivalent d'une "ligne" dans la liste de paquets de Wireshark.
/// </summary>
public sealed class CapturedPacket
{
    public int Number { get; init; }
    public DateTime Timestamp { get; init; }
    public int Length { get; init; }

    public EthernetFrame? Ethernet { get; set; }
    public ArpPacket? Arp { get; set; }
    public IPv4Packet? IPv4 { get; set; }
    public IPv6Packet? IPv6 { get; set; }
    public IcmpPacket? Icmp { get; set; }
    public TcpSegment? Tcp { get; set; }
    public UdpSegment? Udp { get; set; }
    public DnsMessage? Dns { get; set; }
    public TlsClientHello? Tls { get; set; }

    /// <summary>Numero de flux TCP (comme "tcp.stream" dans Wireshark) — null si le paquet n'a pas de couche TCP.</summary>
    public int? TcpStreamIndex { get; set; }

    /// <summary>Protocole "le plus haut" detecte, pour la colonne Protocol.</summary>
    public string TopProtocol =>
        Dns is not null ? "DNS" :
        Icmp is not null ? "ICMP" :
        Tls is not null ? "TLS" :
        Tcp is not null ? "TCP" :
        Udp is not null ? "UDP" :
        Arp is not null ? "ARP" :
        IPv6 is not null ? IPv6.ProtocolName :
        IPv4 is not null ? IPv4.ProtocolName :
        Ethernet is not null ? Ethernet.EtherTypeName :
        "UNKNOWN";

    public string Source =>
        Arp is not null ? Arp.SenderProtocolAddress.ToString() :
        IPv6 is not null ? IPv6.SourceAddress.ToString() :
        IPv4 is not null ? IPv4.SourceAddress.ToString() :
        Ethernet?.SourceMac.ToString() ?? "?";

    public string Destination =>
        Arp is not null ? Arp.TargetProtocolAddress.ToString() :
        IPv6 is not null ? IPv6.DestinationAddress.ToString() :
        IPv4 is not null ? IPv4.DestinationAddress.ToString() :
        Ethernet?.DestinationMac.ToString() ?? "?";

    public string Info
    {
        get
        {
            if (Dns is not null) return BuildDnsInfo(Dns);
            if (Icmp is not null) return $"{Icmp.TypeName} id={Icmp.Identifier} seq={Icmp.Sequence}";
            if (Tls is not null) return Tls.ServerName is { } sni ? $"Client Hello (SNI={sni})" : "Client Hello";
            if (Tcp is not null)
                return $"{Tcp.SourcePort} -> {Tcp.DestinationPort} [{Tcp.FlagsSummary}] Seq={Tcp.SequenceNumber} Ack={Tcp.AcknowledgmentNumber} Win={Tcp.WindowSize} Len={Tcp.PayloadLength}";
            if (Udp is not null) return $"{Udp.SourcePort} -> {Udp.DestinationPort} Len={Udp.PayloadLength}";
            if (Arp is not null) return BuildArpInfo(Arp);
            if (IPv6 is not null) return $"{IPv6.ProtocolName} HopLimit={IPv6.HopLimit}";
            if (IPv4 is not null) return $"{IPv4.ProtocolName} TTL={IPv4.Ttl}";
            return string.Empty;
        }
    }

    private static string BuildDnsInfo(DnsMessage dns)
    {
        string question = dns.Questions.Count > 0 ? $"{dns.Questions[0].TypeName} {dns.Questions[0].Name}" : string.Empty;

        if (!dns.IsResponse)
            return $"Standard query 0x{dns.Id:x4} {question}".TrimEnd();

        var answerTexts = new List<string>();
        foreach (var answer in dns.Answers)
            if (answer.Data is not null)
                answerTexts.Add(answer.Data);

        string answers = answerTexts.Count > 0 ? " " + string.Join(", ", answerTexts) : string.Empty;
        return $"Standard query response 0x{dns.Id:x4} {question}{answers}".TrimEnd();
    }

    private static string BuildArpInfo(ArpPacket arp) => arp.Opcode switch
    {
        1 => $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}",
        2 => $"{arp.SenderProtocolAddress} is at {arp.SenderHardwareAddress}",
        _ => arp.OpcodeName
    };
}