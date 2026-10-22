using System.Diagnostics.Metrics;
using System.Text;
using System.Text.RegularExpressions;
using MiniWireshark.Models;

namespace MiniWireshark.Core.Search;

public static class PacketSearch
{
    public static bool Matches(CapturedPacket packet, string query, bool includePayload) =>
        !string.IsNullOrEmpty(query) && MatchesCore(packet, query, includePayload ? FoldedUtf8(query) : null);

    public static List<int> FindAll(IReadOnlyList<CapturedPacket> packets, string query, bool includePayload)
    {
        var matches = new List<int>();
        if (string.IsNullOrEmpty(query))
            return matches;
        
        byte[]? needle = includePayload ? FoldedUtf8(query) : null;

        for (int i = 0; i < packets.Count; i++)
            if (MatchesCore(packets[i], query, needle))
                matches.Add(i);
        
        return matches;
    }

    public static int NextPosition(IReadOnlyList<int> matches, int currentIndex, bool forward)
    {
        if (matches.Count == 0)
            return -1;
        
        if (forward)
        {
            for (int i = 0; i < matches.Count; i++)
                if (matches[i] > currentIndex)
                    return i;
            
            return 0;
        }

        for (int i = matches.Count - 1; i >= 0; i--)
            if (matches[i] < currentIndex)
                return i;
        
        return matches.Count - 1;
    }

    private static bool MatchesCore(CapturedPacket packet, string query, byte[]? payloadNeedle)
    {
        const StringComparison ignoreCase = StringComparison.OrdinalIgnoreCase;

        if (packet.Number.ToString().Contains(query, ignoreCase)
            || packet.Timestamp.ToString("HH:mm:ss.fff").Contains(query, ignoreCase)
            || packet.Source.Contains(query, ignoreCase)
            || packet.Destination.Contains(query, ignoreCase)
            || packet.TopProtocol.Contains(query, ignoreCase)
            || packet.ProcessDisplay.Contains(query, ignoreCase)
            || packet.Info.Contains(query, ignoreCase))
            return true;
        
        if (payloadNeedle is null)
            return false;
        
        return (packet.Tcp is { } tcp && ContainsFolded(tcp.Payload.Span, payloadNeedle))
            || (packet.Udp is { } udp && ContainsFolded(udp.Payload.Span, payloadNeedle));
    }

    private static byte[] FoldedUtf8(string query)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(query);
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Fold(bytes[i]);
        return bytes;
    }

    private static byte Fold(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;

    private static bool ContainsFolded(ReadOnlySpan<byte> data, byte[] foldedNeedle)
    {
        if (foldedNeedle.Length == 0 || data.Length < foldedNeedle.Length)
            return false;
        
        int last = data.Length - foldedNeedle.Length;
        for (int start = 0; start <= last; start++)
        {
            int j = 0;
            while (j < foldedNeedle.Length && Fold(data[start + j]) == foldedNeedle[j])
                j++;
            
            if (j == foldedNeedle.Length)
                return true;
        }

        return false;
    }
}