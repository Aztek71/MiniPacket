namespace MiniWireshark.Core.Streams;

public sealed class TcpDirectionData
{
    public static readonly TcpDirectionData Empty = new(Array.Empty<byte>(), Array.Empty<(int, int)>(), false);

    private readonly (int Offset, int PacketNumber)[] _marks;

    public TcpDirectionData(byte[] data, (int Offset, int PacketNumber)[] marks, bool hasGap)
    {
        Data = data;
        _marks = marks;
        HasGap = hasGap;
    }

    public byte[] Data { get; }
    public bool HasGap { get; }

    public int PacketNumberAt(int offset)
    {
        int packet = _marks.Length > 0 ? _marks[0].PacketNumber : 0;
        foreach (var mark in _marks)
        {
            if (mark.Offset > offset)
                break;
            packet = mark.PacketNumber;
        }
        return packet;
    }
}

public static class TcpDirectionReassembler
{
    public static TcpDirectionData Reassemble(TcpStream stream, bool fromEndpointA)
    {
        var segments = stream.Segments
            .Where(s => s.FromEndpointA == fromEndpointA && s.Payload.Length > 0)
            .OrderBy(s => s.Timestamp)
            .ThenBy(s => s.PacketNumber)
            .ToList();

        if (segments.Count == 0)
            return TcpDirectionData.Empty;
        
        uint reference = segments[0].SequenceNumber;
        var positioned = segments
            .Select(s => (Relative: (long)(int)(s.SequenceNumber - reference), Segment: s))
            .ToList();

        long minimum = positioned.Min(p => p.Relative);
        var ordered = positioned
            .OrderBy(p => p.Relative)
            .ThenBy(p => p.Segment.PacketNumber)
            .ToList();
        
        var data = new List<byte>();
        var marks = new List<(int Offset, int PacketNumber)>();
        long next = 0;
        bool gap = false;

        foreach (var (relative, segment) in ordered)
        {
            long start = relative - minimum;
            long end = start + segment.Payload.Length;

            if (end <= next)
                continue; // retransmission : on l'ignore dans la conversation reconstituee
        
            if (start > next)
            {
                gap = true;
                break;
            }

            int skip = (int)(next - start);
            marks.Add((data.Count, segment.PacketNumber));
            data.AddRange(skip == 0 ? segment.Payload : segment.Payload.Skip(skip));
            next = end;
        }

        return new TcpDirectionData(data.ToArray(), marks.ToArray(), gap);
    }
}