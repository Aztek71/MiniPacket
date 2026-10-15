namespace MiniWireshark.Dissectors;

/// <summary>
/// Dissection d'un en-tête TCP (20 octets minimum, sans options).
/// Format : [SrcPort:2][DstPort:2][Seq:4][Ack:4][DataOffset/Flags:2][Window:2][Checksum:2][Urgent:2]
/// </summary>
public sealed class TcpSegment
{
    public const int MinHeaderLength = 20;

    public ushort SourcePort { get; init; }
    public ushort DestinationPort { get; init; }
    public uint SequenceNumber { get; init; }
    public uint AcknowledgmentNumber { get; init; }
    public ushort WindowSize { get; init; }

    public bool Fin { get; init; }
    public bool Syn { get; init; }
    public bool Rst { get; init; }
    public bool Psh { get; init; }
    public bool Ack { get; init; }
    public bool Urg { get; init; }

    public int PayloadLength { get; init; }
    public ReadOnlyMemory<byte> Payload { get; init; }

    public string FlagsSummary
    {
        get
        {
            var flags = new List<string>();
            if (Syn) flags.Add("SYN");
            if (Ack) flags.Add("ACK");
            if (Fin) flags.Add("FIN");
            if (Rst) flags.Add("RST");
            if (Psh) flags.Add("PSH");
            if (Urg) flags.Add("URG");
            return flags.Count > 0 ? string.Join(", ", flags) : "-";
        }
    }

    public static TcpSegment? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < MinHeaderLength)
            return null;

        ushort srcPort = (ushort)((raw[0] << 8) | raw[1]);
        ushort dstPort = (ushort)((raw[2] << 8) | raw[3]);
        uint seq = (uint)((raw[4] << 24) | (raw[5] << 16) | (raw[6] << 8) | raw[7]);
        uint ack = (uint)((raw[8] << 24) | (raw[9] << 16) | (raw[10] << 8) | raw[11]);

        byte dataOffsetByte = raw[12];
        int dataOffset = (dataOffsetByte >> 4) * 4; // en octets

        byte flagsByte = raw[13];
        bool fin = (flagsByte & 0x01) != 0;
        bool syn = (flagsByte & 0x02) != 0;
        bool rst = (flagsByte & 0x04) != 0;
        bool psh = (flagsByte & 0x08) != 0;
        bool ackFlag = (flagsByte & 0x10) != 0;
        bool urg = (flagsByte & 0x20) != 0;

        ushort window = (ushort)((raw[14] << 8) | raw[15]);

        if (raw.Length < dataOffset)
            return null;

        var payload = dataOffset < raw.Length
            ? raw.Slice(dataOffset).ToArray()
            : Array.Empty<byte>();

        return new TcpSegment
        {
            SourcePort = srcPort,
            DestinationPort = dstPort,
            SequenceNumber = seq,
            AcknowledgmentNumber = ack,
            WindowSize = window,
            Fin = fin,
            Syn = syn,
            Rst = rst,
            Psh = psh,
            Ack = ackFlag,
            Urg = urg,
            PayloadLength = payload.Length,
            Payload = payload
        };
    }
}
