using System.Net;
using System.Net.NetworkInformation;

namespace MiniWireshark.Dissectors;

public sealed class ArpPacket
{
    public const int MinHeaderLength = 8;
    
    public ushort Opcode { get; init; }
    public PhysicalAddress SenderHardwareAddress { get; init; } = PhysicalAddress.None;
    public IPAddress SenderProtocolAddress { get; init; } = IPAddress.None;
    public PhysicalAddress TargetHardwareAddress { get; init; } = PhysicalAddress.None;
    public IPAddress TargetProtocolAddress { get; init; } = IPAddress.None;

    public string OpcodeName => Opcode switch
    {
        1 => "Request",
        2 => "Reply",
        _ => $"Opcode {Opcode}"
    };

    public static ArpPacket? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < MinHeaderLength)
            return null;

        byte hwLen = raw[4];
        byte protoLen = raw[5];
        ushort opcode = (ushort)((raw[6] << 8) | raw[7]);

        int totalLength = 8 + 2 * hwLen + 2 * protoLen;
        if (raw.Length < totalLength || hwLen == 0 || protoLen == 0)
            return null;

        int offset = 8;
        var senderHw = new PhysicalAddress(raw.Slice(offset, hwLen).ToArray()); offset += hwLen;
        var senderProto = new IPAddress(raw.Slice(offset, protoLen).ToArray()); offset += protoLen;
        var targetHw = new PhysicalAddress(raw.Slice(offset, hwLen).ToArray()); offset += hwLen;
        var targetProto = new IPAddress(raw.Slice(offset, protoLen).ToArray());

        return new ArpPacket
        {
            Opcode = opcode,
            SenderHardwareAddress = senderHw,
            SenderProtocolAddress = senderProto,
            TargetHardwareAddress = targetHw,
            TargetProtocolAddress = targetProto
        };
    }
}

