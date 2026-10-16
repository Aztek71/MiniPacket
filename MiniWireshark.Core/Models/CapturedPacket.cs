using System.ComponentModel;
using MiniWireshark.Core.Analysis;
using MiniWireshark.Dissectors;

namespace MiniWireshark.Models;

/// <summary>
/// Represente un paquet capture, une fois entierement disseque.
/// C'est l'equivalent d'une "ligne" dans la liste de paquets de Wireshark.
/// Implemente INotifyPropertyChanged : une anomalie detectee apres coup (SYN sans reponse) met la ligne a jour.
/// </summary>
public sealed class CapturedPacket : INotifyPropertyChanged
{
    private readonly List<PacketAnomaly> _anomalies = new();

    public event PropertyChangedEventHandler? PropertyChanged;

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

    /// <summary>Anomalies relevees sur ce paquet (retransmission, RST, TTL tres bas...).</summary>
    public IReadOnlyList<PacketAnomaly> Anomalies => _anomalies;

    /// <summary>
    /// Ajoute une anomalie. Avant la publication du paquet (thread de capture) personne n'ecoute encore ;
    /// apres, l'appelant doit etre sur le thread UI, ou les liaisons de la liste reagissent.
    /// </summary>
    public void AddAnomaly(PacketAnomaly anomaly)
    {
        if (_anomalies.Any(a => a.Code == anomaly.Code && a.Label == anomaly.Label))
            return;

        _anomalies.Add(anomaly);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Anomalies)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Info)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(RowColorKey)));
    }

    /// <summary>La gravite la plus elevee parmi les anomalies, ou null s'il n'y en a pas.</summary>
    public AnomalySeverity? HighestSeverity => _anomalies.Count == 0 ? null : _anomalies.Max(a => a.Severity);

    /// <summary>
    /// Cle de couleur de la ligne : une anomalie d'avertissement ou d'erreur prime sur la couleur du protocole.
    /// </summary>
    public string RowColorKey => HighestSeverity switch
    {
        AnomalySeverity.Error => "ANOMALY_ERROR",
        AnomalySeverity.Warning => "ANOMALY_WARNING",
        _ => TopProtocol
    };

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

    /// <summary>Colonne Info : les etiquettes d'anomalies entre crochets, puis le resume du paquet.</summary>
    public string Info
    {
        get
        {
            string summary = BaseInfo;
            if (_anomalies.Count == 0)
                return summary;

            string tags = string.Join(" ", _anomalies.Select(a => $"[{a.Label}]"));
            return summary.Length == 0 ? tags : $"{tags} {summary}";
        }
    }

    private string BaseInfo
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