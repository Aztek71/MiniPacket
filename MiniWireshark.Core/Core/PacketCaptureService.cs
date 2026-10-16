using MiniWireshark.Core.Stats;
using MiniWireshark.Core.Streams;
using MiniWireshark.Core.Analysis;
using MiniWireshark.Dissectors;
using MiniWireshark.Models;
using SharpPcap;
using SharpPcap.LibPcap;

namespace MiniWireshark.Core;

/// <summary>
/// Encapsule SharpPcap : liste les interfaces, ouvre une capture,
/// et transforme chaque trame brute en CapturedPacket disseque.
/// </summary>
public sealed class PacketCaptureService : IDisposable
{
    private ICaptureDevice? _device;
    private int _packetCounter;

    /// <summary>Suivi des flux TCP de la capture en cours — permet le "Follow TCP Stream".</summary>
    public TcpStreamTracker StreamTracker { get; } = new();

    /// <summary>Statistiques en direct de la capture en cours (paquets/s, repartition protocole, top talkers).</summary>
    public CaptureStatistics Statistics { get; } = new();

    /// <summary>Releve les anomalies reseau (retransmissions, RST, SYN sans reponse...).</summary>
    public PacketAnalyzer Analyzer { get; } = new();

    /// <summary>Declenche a chaque paquet entierement disseque.</summary>
    public event Action<CapturedPacket>? OnPacketCaptured;

    /// <summary>Liste toutes les interfaces reseau disponibles pour la capture.</summary>
    public static IReadOnlyList<ICaptureDevice> ListDevices()
    {
        return CaptureDeviceList.Instance.ToList();
    }

    /// <summary>
    /// Demarre la capture sur l'interface donnee.
    /// mode Promiscuous = capture tout le trafic visible, pas seulement celui adresse a la machine.
    /// </summary>
    public void Start(ICaptureDevice device, string? bpfFilter = null)
    {
        StreamTracker.Reset();
        Statistics.Reset();
        Analyzer.Reset();

        _device = device;
        _device.OnPacketArrival += HandleRawPacket;

        // Argument positionnel plutot que nomme : le nom du 2e parametre de Open()
        // a change selon les versions de SharpPcap (readTimeoutMilliseconds / read_timeout).
        _device.Open(DeviceModes.Promiscuous, 1000);

        // Filtre BPF facon "tcpdump", ex: "tcp port 80" ou "host 192.168.1.1"
        if (!string.IsNullOrWhiteSpace(bpfFilter))
            _device.Filter = bpfFilter;

        _device.StartCapture();
    }

    public void Stop()
    {
        if (_device is null) return;
        _device.StopCapture();
        _device.Close();
    }

    private void HandleRawPacket(object sender, PacketCapture e)
    {
        var raw = e.Data.ToArray();
        var packet = Dissect(raw, e.Header.Timeval.Date);
        OnPacketCaptured?.Invoke(packet);
    }

    /// <summary>
    /// Pipeline de dissection couche par couche : Ethernet -> (ARP | IPv4 | IPv6) -> (ICMP | TCP | UDP) -> DNS.
    /// Chaque etage ne consomme que son propre en-tete et passe le reste au suivant.
    /// </summary>
    private CapturedPacket Dissect(byte[] raw, DateTime timestamp)
    {
        var packet = new CapturedPacket
        {
            Number = ++_packetCounter,
            Timestamp = timestamp,
            Length = raw.Length
        };

        var ethernet = EthernetFrame.Parse(raw);
        packet.Ethernet = ethernet;
        if (ethernet is null)
            return packet;

        switch (ethernet.EtherType)
        {
            case 0x0800: // IPv4
                DissectIPv4(packet, ethernet.Payload.Span);
                break;
            case 0x86DD: // IPv6
                DissectIPv6(packet, ethernet.Payload.Span);
                break;
            case 0x0806: // ARP
                packet.Arp = ArpPacket.Parse(ethernet.Payload.Span);
                break;
        }

        // Un seul point d'appel, apres la dissection complete (IPv4 ou IPv6) : packet.Tcp est deja renseigne si present.
        StreamTracker.Track(packet);
        Analyzer.Analyze(packet);
        Statistics.Record(packet);

        return packet;
    }

    private static void DissectIPv4(CapturedPacket packet, ReadOnlySpan<byte> payload)
    {
        var ipv4 = IPv4Packet.Parse(payload);
        packet.IPv4 = ipv4;
        if (ipv4 is null)
            return;

        switch (ipv4.Protocol)
        {
            case 1: // ICMP
                packet.Icmp = IcmpPacket.Parse(ipv4.Payload.Span);
                break;
            case 6: // TCP
                packet.Tcp = TcpSegment.Parse(ipv4.Payload.Span);
                TryDissectTls(packet);
                break;
            case 17: // UDP
                packet.Udp = UdpSegment.Parse(ipv4.Payload.Span);
                TryDissectDns(packet);
                break;
        }
    }

    private static void DissectIPv6(CapturedPacket packet, ReadOnlySpan<byte> payload)
    {
        var ipv6 = IPv6Packet.Parse(payload);
        packet.IPv6 = ipv6;
        if (ipv6 is null)
            return;

        switch (ipv6.NextHeader)
        {
            case 58: // ICMPv6
                packet.Icmp = IcmpPacket.Parse(ipv6.Payload.Span);
                break;
            case 6: // TCP
                packet.Tcp = TcpSegment.Parse(ipv6.Payload.Span);
                TryDissectTls(packet);
                break;
            case 17: // UDP
                packet.Udp = UdpSegment.Parse(ipv6.Payload.Span);
                TryDissectDns(packet);
                break;
        }
    }

    /// <summary>DNS tourne sur UDP port 53 (source ou destination) : on tente de le parser par-dessus l'UDP deja disseque.</summary>
    
    /// <summary>Tente d'extraire un ClientHello TLS (et son SNI) du payload TCP, quel que soit le port.</summary>
    private static void TryDissectTls(CapturedPacket packet)
    {
        if (packet.Tcp is not { PayloadLength: > 0 } tcp)
            return;

        packet.Tls = TlsClientHello.Parse(tcp.Payload.Span);
    }
    
    private static void TryDissectDns(CapturedPacket packet)
    {
        if (packet.Udp is not { } udp)
            return;
        if (udp.SourcePort != 53 && udp.DestinationPort != 53)
            return;

        packet.Dns = DnsMessage.Parse(udp.Payload.ToArray());
    }

    public void Dispose()
    {
        Stop();
        _device?.Dispose();
    }
}