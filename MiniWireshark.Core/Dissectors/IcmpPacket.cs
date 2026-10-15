namespace MiniWireshark.Dissectors;

public sealed class IcmpPacket
{
    public const int MinHeaderLength = 4;
    
    public byte Type { get; init; }
    public byte Code { get; init; }
    public ushort Identifier { get; init; }
    public ushort Sequence { get; init; }

    public string TypeName => Type switch
    {
        0 => "Echo (ping) reply",
        3 => "Destination unreachable",
        8 => "Echo (ping) request",
        11 => "Time exceeded",
        1 => "Destination unreachable (v6)",
        2 => "Packet too big (v6)",
        4 => "Parameter problem (v6)",
        128 => "Echo (ping) request (v6)",
        129 => "Echo (ping) reply (v6)",
        133 => "Router solicitation (v6)",
        134 => "Router advertisement (v6)",
        135 => "Neighbor solicitation (v6)",
        136 => "Neighbor advertisement (v6)",
        _ => $"Type {Type}"
    };

    public static IcmpPacket? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < MinHeaderLength)
            return null;

        byte type = raw[0];
        byte code = raw[1];
        ushort identifier = 0;
        ushort sequence = 0;

        bool isEcho = type is 0 or 8 or 128 or 129;
        if (isEcho && raw.Length >= 8)
        {
            identifier = (ushort)((raw[4] << 8) | raw[5]);
            sequence = (ushort)((raw[6] << 8) | raw[7]);
        }

        return new IcmpPacket
        {
            Type = type,
            Code = code,
            Identifier = identifier,
            Sequence = sequence
        };
    }
}