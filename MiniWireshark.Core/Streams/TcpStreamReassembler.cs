namespace MiniWireshark.Core.Streams;

/// <summary>Un morceau contigu de conversation dans un seul sens (fusion des segments consecutifs du meme cote), en texte.</summary>
public readonly record struct TcpStreamChunk(bool FromEndpointA, string Text);

/// <summary>Meme chose, mais en octets bruts (pour l'hexdump et l'analyse TLS).</summary>
public readonly record struct TcpStreamDataChunk(bool FromEndpointA, byte[] Data);

/// <summary>
/// Reconstitue le contenu applicatif d'un flux TCP a partir de ses segments captures,
/// facon "Follow TCP Stream" de Wireshark : ordre chronologique de capture, retransmissions
/// exactes (meme numero de sequence deja vu dans le meme sens) ignorees.
/// </summary>
public static class TcpStreamReassembler
{
    public static IReadOnlyList<TcpStreamDataChunk> BuildDataChunks(TcpStream stream)
    {
        var seenSequences = new Dictionary<bool, HashSet<uint>>
        {
            [true] = new(),
            [false] = new()
        };

        var chunks = new List<(bool FromEndpointA, List<byte> Data)>();

        foreach (var segment in stream.Segments.OrderBy(s => s.Timestamp).ThenBy(s => s.PacketNumber))
        {
            if (!seenSequences[segment.FromEndpointA].Add(segment.SequenceNumber))
                continue; // retransmission : on l'ignore dans la conversation reconstituee

            if (chunks.Count > 0 && chunks[^1].FromEndpointA == segment.FromEndpointA)
                chunks[^1].Data.AddRange(segment.Payload);
            else
                chunks.Add((segment.FromEndpointA, new List<byte>(segment.Payload)));
        }

        return chunks.Select(c => new TcpStreamDataChunk(c.FromEndpointA, c.Data.ToArray())).ToList();
    }

    public static IReadOnlyList<TcpStreamChunk> BuildConversationChunks(TcpStream stream) =>
        BuildDataChunks(stream)
            .Select(c => new TcpStreamChunk(c.FromEndpointA, DecodeAsText(c.Data)))
            .ToList();

    /// <summary>Convertit les octets en texte affichable : les octets non imprimables deviennent un '.', comme dans Wireshark.</summary>
    private static string DecodeAsText(byte[] payload)
    {
        var chars = new char[payload.Length];
        for (int i = 0; i < payload.Length; i++)
        {
            byte b = payload[i];
            chars[i] = (b >= 0x20 && b < 0x7F) || b is (byte)'\n' or (byte)'\r' or (byte)'\t'
                ? (char)b
                : '.';
        }
        return new string(chars);
    }
}