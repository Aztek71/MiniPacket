using MiniWireshark.Models;

namespace MiniWireshark.Core.Streams;

/// <summary>Cle canonique d'un flux TCP : independante du sens (src/dst) du paquet qui l'a declenchee.</summary>
internal readonly struct TcpStreamKey : IEquatable<TcpStreamKey>
{
    public TcpEndpoint EndpointA { get; }
    public TcpEndpoint EndpointB { get; }

    private TcpStreamKey(TcpEndpoint a, TcpEndpoint b)
    {
        EndpointA = a;
        EndpointB = b;
    }

    public static TcpStreamKey Create(TcpEndpoint src, TcpEndpoint dst) =>
        Compare(src, dst) <= 0 ? new TcpStreamKey(src, dst) : new TcpStreamKey(dst, src);

    private static int Compare(TcpEndpoint x, TcpEndpoint y)
    {
        int c = string.CompareOrdinal(x.Ip, y.Ip);
        return c != 0 ? c : x.Port.CompareTo(y.Port);
    }

    public bool Equals(TcpStreamKey other) => EndpointA.Equals(other.EndpointA) && EndpointB.Equals(other.EndpointB);
    public override bool Equals(object? obj) => obj is TcpStreamKey other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(EndpointA, EndpointB);
}

/// <summary>
/// Suit chaque connexion TCP vue pendant une capture : attribue un numero de flux stable
/// (comme "tcp.stream" dans Wireshark) et accumule les segments pour la reconstitution ulterieure.
/// </summary>
public sealed class TcpStreamTracker
{
    private readonly Dictionary<TcpStreamKey, TcpStream> _streams = new();
    private int _nextStreamIndex;

    public IReadOnlyCollection<TcpStream> Streams => _streams.Values;

    /// <summary>Efface tous les flux suivis (appele au demarrage d'une nouvelle capture).</summary>
    public void Reset()
    {
        _streams.Clear();
        _nextStreamIndex = 0;
    }

    /// <summary>
    /// Rattache le paquet TCP donne a son flux (le cree si besoin), marque CapturedPacket.TcpStreamIndex,
    /// et accumule son payload pour la reconstitution. Ne fait rien si le paquet n'a pas de couche TCP+IP.
    /// </summary>
    public void Track(CapturedPacket packet)
    {
        if (packet.Tcp is not { } tcp)
            return;

        string? srcIp = packet.IPv4?.SourceAddress.ToString() ?? packet.IPv6?.SourceAddress.ToString();
        string? dstIp = packet.IPv4?.DestinationAddress.ToString() ?? packet.IPv6?.DestinationAddress.ToString();
        if (srcIp is null || dstIp is null)
            return;

        var src = new TcpEndpoint(srcIp, tcp.SourcePort);
        var dst = new TcpEndpoint(dstIp, tcp.DestinationPort);
        var key = TcpStreamKey.Create(src, dst);

        if (!_streams.TryGetValue(key, out var stream))
        {
            stream = new TcpStream
            {
                StreamIndex = _nextStreamIndex++,
                EndpointA = key.EndpointA,
                EndpointB = key.EndpointB
            };
            _streams[key] = stream;
        }

        bool fromA = src.Equals(stream.EndpointA);

        if (tcp.PayloadLength > 0)
        {
            stream.Segments.Add(new TcpStreamSegment
            {
                PacketNumber = packet.Number,
                Timestamp = packet.Timestamp,
                FromEndpointA = fromA,
                SequenceNumber = tcp.SequenceNumber,
                Payload = tcp.Payload.ToArray()
            });
        }

        packet.TcpStreamIndex = stream.StreamIndex;
    }

    public TcpStream? GetStream(int streamIndex)
    {
        foreach (var stream in _streams.Values)
            if (stream.StreamIndex == streamIndex)
                return stream;
        return null;
    }
}