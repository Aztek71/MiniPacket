using MiniWireshark.Models;

namespace MiniWireshark.Core.Stats;

public sealed class TalkerStats
{
    public required string Address { get; init; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
}

/// <summary>
/// Agrege des statistiques en direct sur la capture en cours : paquets/seconde (fenetre glissante),
/// repartition par protocole, "top talkers" (adresses qui echangent le plus d'octets).
/// Thread-safe : Record() est appele depuis le thread de capture, les Get*() depuis le thread UI.
/// </summary>
public sealed class CaptureStatistics
{
    private readonly object _lock = new();
    private readonly Dictionary<string, int> _protocolCounts = new();
    private readonly Dictionary<string, TalkerStats> _talkers = new();
    private readonly Dictionary<long, int> _perSecondBuckets = new();

    public int TotalPackets { get; private set; }
    public long TotalBytes { get; private set; }

    public void Reset()
    {
        lock (_lock)
        {
            _protocolCounts.Clear();
            _talkers.Clear();
            _perSecondBuckets.Clear();
            TotalPackets = 0;
            TotalBytes = 0;
        }
    }

    public void Record(CapturedPacket packet)
    {
        lock (_lock)
        {
            TotalPackets++;
            TotalBytes += packet.Length;

            string proto = packet.TopProtocol;
            _protocolCounts[proto] = _protocolCounts.GetValueOrDefault(proto) + 1;

            // Top talkers : uniquement les adresses de couche reseau (IP / ARP). Sans couche IP, Source/Destination
            // retombent sur les MAC (broadcast, LLDP...), qui fausseraient le classement.
            bool hasNetworkAddress = packet.IPv4 is not null || packet.IPv6 is not null || packet.Arp is not null;
            if (hasNetworkAddress)
            {
                AddTalker(packet.Source, packet.Length);
                if (packet.Destination != packet.Source)
                    AddTalker(packet.Destination, packet.Length);
            }

            // Horodatage "mur" (pas celui du paquet) : les secondes sans paquet apparaissent
            // naturellement a 0 quand on interroge GetPacketsPerSecond, meme pendant un trou de trafic.
            long bucketKey = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            _perSecondBuckets[bucketKey] = _perSecondBuckets.GetValueOrDefault(bucketKey) + 1;

            // Purge des secondes trop anciennes pour ne pas accumuler indefiniment sur une longue capture.
            if (_perSecondBuckets.Count > 150)
            {
                long cutoff = bucketKey - 120;
                foreach (var oldKey in _perSecondBuckets.Keys.Where(k => k < cutoff).ToList())
                    _perSecondBuckets.Remove(oldKey);
            }
        }
    }

    private void AddTalker(string address, int bytes)
    {
        if (!_talkers.TryGetValue(address, out var stats))
        {
            stats = new TalkerStats { Address = address };
            _talkers[address] = stats;
        }
        stats.PacketCount++;
        stats.ByteCount += bytes;
    }

    /// <summary>Repartition par protocole, du plus frequent au moins frequent.</summary>
    public IReadOnlyList<(string Protocol, int Count)> GetProtocolBreakdown()
    {
        lock (_lock)
            return _protocolCounts.Select(kv => (kv.Key, kv.Value)).OrderByDescending(x => x.Value).ToList();
    }

    /// <summary>Les adresses qui ont echange le plus d'octets (emission + reception confondues).</summary>
    public IReadOnlyList<TalkerStats> GetTopTalkers(int count)
    {
        lock (_lock)
            return _talkers.Values.OrderByDescending(t => t.ByteCount).Take(count).ToList();
    }

    /// <summary>Nombre de paquets par seconde sur les <paramref name="lastSeconds"/> dernieres secondes (plus ancien en premier).</summary>
    public IReadOnlyList<int> GetPacketsPerSecond(int lastSeconds)
    {
        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var result = new int[lastSeconds];
            for (int i = 0; i < lastSeconds; i++)
            {
                long key = now - (lastSeconds - 1 - i);
                result[i] = _perSecondBuckets.GetValueOrDefault(key);
            }
            return result;
        }
    }
}