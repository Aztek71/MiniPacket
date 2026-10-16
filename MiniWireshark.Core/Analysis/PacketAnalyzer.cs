using System.Net;
using MiniWireshark.Models;

namespace MiniWireshark.Core.Analysis;

/// <summary>
/// Releve les anomalies reseau au fil de la capture, a la facon de l'analyse TCP de Wireshark :
/// retransmissions, paquets hors d'ordre, segments non captures, ACK dupliques, fenetre nulle, keep-alive, RST,
/// connexion refusee, SYN sans reponse, TTL tres bas, ICMP injoignable.
/// Analyze() s'appelle sur le thread de capture, avant la publication du paquet ; ExpirePendingSyns() sur le thread UI.
/// </summary>
public sealed class PacketAnalyzer
{
    private const int MaxRememberedSegments = 4096;
    private const int MaxLostRanges = 64;
    private const int LowTtlThreshold = 5;

    // Un segment qui comble un trou arrive-t-il "tout de suite" ? Alors c'est du desordre, pas une retransmission.
    private const double ReorderingWindowMs = 3.0;

    private static readonly TimeSpan SynTimeout = TimeSpan.FromSeconds(3);

    private readonly object _lock = new();
    private readonly Dictionary<int, StreamState> _streams = new();
    private readonly Dictionary<string, (CapturedPacket Packet, DateTime Since)> _pendingSyns = new();

    private sealed class LostRange
    {
        public long Start;
        public long End;
        public DateTime Time;
    }

    private sealed class DirectionState
    {
        public bool Initialized;
        public long LastExtended;   // plus grand numero de sequence "deroule" vu (voir Unwrap)
        public long Next;           // numero de sequence attendu pour le prochain segment dans l'ordre
        public HashSet<(long Start, int Length)> Seen { get; } = new();
        public Queue<(long Start, int Length)> SeenOrder { get; } = new();
        public List<LostRange> Lost { get; } = new();
        public bool HasAck;
        public uint LastAck;
        public ushort LastWindow;
        public int DupAckCount;
    }

    private sealed class StreamState
    {
        public string FirstSenderIp = string.Empty;
        public ushort FirstSenderPort;
        public DirectionState[] Directions { get; } = { new(), new() };
    }

    public void Reset()
    {
        lock (_lock)
        {
            _streams.Clear();
            _pendingSyns.Clear();
        }
    }

    /// <summary>Analyse un paquet et lui ajoute les anomalies detectees. A appeler apres le suivi des flux TCP (TcpStreamIndex).</summary>
    public void Analyze(CapturedPacket packet)
    {
        lock (_lock)
        {
            AnalyzeTtl(packet);
            AnalyzeIcmp(packet);

            if (packet.Tcp is not null && packet.TcpStreamIndex is { } streamIndex)
                AnalyzeTcp(packet, streamIndex);
        }
    }

    /// <summary>
    /// SYN restes sans reponse (ni SYN/ACK ni RST) depuis plus de 3 secondes. A appeler regulierement pendant la capture ;
    /// le resultat est a appliquer par l'appelant (sur le thread UI) avec CapturedPacket.AddAnomaly.
    /// </summary>
    public IReadOnlyList<(CapturedPacket Packet, PacketAnomaly Anomaly)> ExpirePendingSyns() =>
        ExpirePendingSyns(DateTime.UtcNow);

    public IReadOnlyList<(CapturedPacket Packet, PacketAnomaly Anomaly)> ExpirePendingSyns(DateTime now)
    {
        var expired = new List<(CapturedPacket, PacketAnomaly)>();

        lock (_lock)
        {
            foreach (var entry in _pendingSyns.ToList())
            {
                if (now - entry.Value.Since < SynTimeout)
                    continue;

                _pendingSyns.Remove(entry.Key);
                expired.Add((entry.Value.Packet, new PacketAnomaly(
                    "syn_no_response", "SYN sans réponse",
                    "Ce SYN n'a reçu ni SYN/ACK ni RST : hôte injoignable, port filtré par un pare-feu, ou paquets perdus.",
                    AnomalySeverity.Error)));
            }
        }

        return expired;
    }

    // ----- IP / ICMP -----

    private static void AnalyzeTtl(CapturedPacket packet)
    {
        int? ttl = packet.IPv4?.Ttl ?? packet.IPv6?.HopLimit;
        if (ttl is null || ttl > LowTtlThreshold)
            return;

        // Multicast et broadcast utilisent volontairement un TTL de 1 (IGMP, mDNS, decouverte...) : pas une anomalie.
        IPAddress? destination = packet.IPv4?.DestinationAddress ?? packet.IPv6?.DestinationAddress;
        if (destination is null || IsMulticastOrBroadcast(destination))
            return;

        packet.AddAnomaly(new PacketAnomaly(
            "low_ttl", $"TTL très bas ({ttl})",
            $"Le TTL / hop limit de ce paquet vaut {ttl} : il a traversé presque tout son budget de sauts, " +
            "ce qui arrive avec un traceroute ou un routage en boucle.",
            AnomalySeverity.Warning));
    }

    private static bool IsMulticastOrBroadcast(IPAddress address)
    {
        if (address.IsIPv6Multicast)
            return true;

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && (bytes[0] is >= 224 and <= 239 || bytes.All(b => b == 255));
    }

    private static void AnalyzeIcmp(CapturedPacket packet)
    {
        if (packet.Icmp is not { } icmp)
            return;

        bool v6 = packet.IPv6 is not null;   // les numeros de type ICMP ne sont pas les memes en IPv4 et IPv6

        if ((!v6 && icmp.Type == 3) || (v6 && icmp.Type == 1))
        {
            packet.AddAnomaly(new PacketAnomaly(
                "icmp_unreachable", "ICMP destination injoignable",
                "Un routeur ou l'hôte signale que la destination (ou le port) est injoignable.",
                AnomalySeverity.Warning));
        }
        else if ((!v6 && icmp.Type == 11) || (v6 && icmp.Type == 3))
        {
            packet.AddAnomaly(new PacketAnomaly(
                "icmp_time_exceeded", "ICMP temps dépassé",
                "Le TTL d'un paquet a expiré en route (traceroute, ou boucle de routage).",
                AnomalySeverity.Info));
        }
    }

    // ----- TCP -----

    private void AnalyzeTcp(CapturedPacket packet, int streamIndex)
    {
        var tcp = packet.Tcp!;
        string? srcIp = packet.IPv4?.SourceAddress.ToString() ?? packet.IPv6?.SourceAddress.ToString();
        string? dstIp = packet.IPv4?.DestinationAddress.ToString() ?? packet.IPv6?.DestinationAddress.ToString();
        if (srcIp is null || dstIp is null)
            return;

        if (!_streams.TryGetValue(streamIndex, out var stream))
        {
            stream = new StreamState { FirstSenderIp = srcIp, FirstSenderPort = tcp.SourcePort };
            _streams[streamIndex] = stream;
        }

        int dirIndex = srcIp == stream.FirstSenderIp && tcp.SourcePort == stream.FirstSenderPort ? 0 : 1;
        var dir = stream.Directions[dirIndex];
        var other = stream.Directions[1 - dirIndex];

        TrackHandshake(packet, srcIp, dstIp);

        int sequenceLength = tcp.PayloadLength + (tcp.Syn ? 1 : 0) + (tcp.Fin ? 1 : 0);
        long extended = Unwrap(dir, tcp.SequenceNumber);

        if (!dir.Initialized)
        {
            // Premier paquet vu dans ce sens (la capture a peut-etre commence en cours de route) : rien a comparer.
            dir.Initialized = true;
            dir.LastExtended = extended;
            dir.Next = extended + sequenceLength;
            Remember(dir, extended, sequenceLength);
        }
        else
        {
            bool keepAlive = !tcp.Syn && !tcp.Fin && !tcp.Rst && tcp.PayloadLength <= 1 && extended == dir.Next - 1;

            if (keepAlive)
            {
                packet.AddAnomaly(new PacketAnomaly(
                    "keep_alive", "TCP Keep-Alive",
                    "Sonde de maintien de connexion : numéro de séquence inférieur d'une unité à celui attendu.",
                    AnomalySeverity.Info));
            }
            else if (sequenceLength > 0)
            {
                AnalyzeSegment(packet, dir, extended, sequenceLength);
            }

            dir.LastExtended = Math.Max(dir.LastExtended, extended);
        }

        AnalyzeAcknowledgment(packet, dir, other);

        if (tcp.WindowSize == 0 && !tcp.Syn && !tcp.Fin && !tcp.Rst)
        {
            packet.AddAnomaly(new PacketAnomaly(
                "zero_window", "TCP Zero Window",
                "Le récepteur annonce une fenêtre de réception nulle : il demande à l'émetteur de cesser d'envoyer.",
                AnomalySeverity.Warning));
        }
    }

    /// <summary>Suit les SYN en attente de reponse, et reconnait un RST en reponse a un SYN (connexion refusee).</summary>
    private void TrackHandshake(CapturedPacket packet, string srcIp, string dstIp)
    {
        var tcp = packet.Tcp!;
        string forward = $"{srcIp}:{tcp.SourcePort}>{dstIp}:{tcp.DestinationPort}";
        string reverse = $"{dstIp}:{tcp.DestinationPort}>{srcIp}:{tcp.SourcePort}";

        if (tcp.Syn && !tcp.Ack)
        {
            if (!_pendingSyns.ContainsKey(forward))
                _pendingSyns[forward] = (packet, DateTime.UtcNow);
        }
        else if (tcp.Syn && tcp.Ack)
        {
            _pendingSyns.Remove(reverse);
        }
        else if (tcp.Rst)
        {
            if (_pendingSyns.Remove(reverse))
            {
                packet.AddAnomaly(new PacketAnomaly(
                    "connection_refused", "TCP Connexion refusée",
                    "Le serveur a répondu au SYN par un RST : aucun service n'écoute sur ce port.",
                    AnomalySeverity.Error));
            }
            else
            {
                packet.AddAnomaly(new PacketAnomaly(
                    "reset", "TCP RST",
                    "Connexion réinitialisée brutalement (fermeture anormale, ou paquet refusé par un pare-feu).",
                    AnomalySeverity.Warning));
            }
        }
    }

    private static void AnalyzeSegment(CapturedPacket packet, DirectionState dir, long start, int length)
    {
        long end = start + length;

        if (start > dir.Next)
        {
            // Trou : des octets entre dir.Next et start n'ont pas ete captures (perdus, ou pas encore arrives).
            packet.AddAnomaly(new PacketAnomaly(
                "lost_segment", "TCP Previous segment not captured",
                $"Il manque {start - dir.Next} octet(s) de données avant ce segment : paquet perdu ou non capturé.",
                AnomalySeverity.Warning));

            dir.Lost.Add(new LostRange { Start = dir.Next, End = start, Time = packet.Timestamp });
            if (dir.Lost.Count > MaxLostRanges)
                dir.Lost.RemoveAt(0);

            dir.Next = end;
        }
        else if (start == dir.Next)
        {
            dir.Next = end;   // segment attendu, dans l'ordre
        }
        else if (dir.Seen.Contains((start, length)))
        {
            packet.AddAnomaly(Retransmission("Ce segment (mêmes octets) a déjà été vu : l'émetteur l'a envoyé une seconde fois."));
        }
        else
        {
            var range = dir.Lost.FirstOrDefault(r => start >= r.Start && end <= r.End);
            if (range is not null)
            {
                // Le segment comble un trou : desordre s'il arrive aussitot, retransmission sinon.
                bool immediate = (packet.Timestamp - range.Time).TotalMilliseconds < ReorderingWindowMs;
                packet.AddAnomaly(immediate
                    ? new PacketAnomaly("out_of_order", "TCP Out-Of-Order",
                        "Ce segment comble un trou laissé par un segment plus récent arrivé avant lui : paquets reçus dans le désordre.",
                        AnomalySeverity.Info)
                    : Retransmission("Ce segment comble un trou resté ouvert : l'émetteur a retransmis des données perdues."));
                ShrinkLostRange(dir, range, start, end);
            }
            else
            {
                packet.AddAnomaly(Retransmission("Ces octets chevauchent des données déjà vues (retransmission, éventuellement redécoupée)."));
                if (end > dir.Next)
                    dir.Next = end;
            }
        }

        Remember(dir, start, length);
    }

    private static PacketAnomaly Retransmission(string description) =>
        new("retransmission", "TCP Retransmission", description, AnomalySeverity.Warning);

    /// <summary>ACK dupliques : meme accuse, meme fenetre, sans donnees, alors que l'autre cote a des donnees non acquittees.</summary>
    private static void AnalyzeAcknowledgment(CapturedPacket packet, DirectionState dir, DirectionState other)
    {
        var tcp = packet.Tcp!;
        if (!tcp.Ack)
            return;

        bool pureAck = !tcp.Syn && !tcp.Fin && !tcp.Rst && tcp.PayloadLength == 0;
        bool outstanding = other.Initialized && Unwrap(other, tcp.AcknowledgmentNumber) < other.Next;

        if (pureAck && dir.HasAck && tcp.AcknowledgmentNumber == dir.LastAck && tcp.WindowSize == dir.LastWindow && outstanding)
        {
            dir.DupAckCount++;
            int n = dir.DupAckCount;
            packet.AddAnomaly(new PacketAnomaly(
                "duplicate_ack", $"TCP Dup ACK #{n}",
                n >= 3
                    ? "Troisième ACK dupliqué ou plus : l'émetteur va déclencher une retransmission rapide."
                    : "Le récepteur répète le même accusé de réception : il attend un segment qui n'est pas arrivé.",
                n >= 3 ? AnomalySeverity.Warning : AnomalySeverity.Info));
        }
        else
        {
            dir.DupAckCount = 0;
        }

        dir.HasAck = true;
        dir.LastAck = tcp.AcknowledgmentNumber;
        dir.LastWindow = tcp.WindowSize;
    }

    /// <summary>Retire de la liste des trous la partie qu'un segment vient de combler.</summary>
    private static void ShrinkLostRange(DirectionState dir, LostRange range, long start, long end)
    {
        if (start == range.Start && end == range.End)
        {
            dir.Lost.Remove(range);
        }
        else if (start == range.Start)
        {
            range.Start = end;
        }
        else if (end == range.End)
        {
            range.End = start;
        }
        else
        {
            dir.Lost.Add(new LostRange { Start = end, End = range.End, Time = range.Time });
            range.End = start;
        }
    }

    private static void Remember(DirectionState dir, long start, int length)
    {
        if (dir.Seen.Add((start, length)))
            dir.SeenOrder.Enqueue((start, length));

        while (dir.SeenOrder.Count > MaxRememberedSegments)
            dir.Seen.Remove(dir.SeenOrder.Dequeue());
    }

    /// <summary>
    /// Numero de sequence 32 bits "deroule" en 64 bits par rapport au dernier vu dans ce sens : un flux qui passe
    /// de 4 294 967 295 a 0 continue de croitre au lieu de sembler revenir en arriere.
    /// </summary>
    private static long Unwrap(DirectionState dir, uint sequence)
    {
        if (!dir.Initialized)
            return sequence;

        long delta = (int)(sequence - (uint)dir.LastExtended);
        return dir.LastExtended + delta;
    }
}