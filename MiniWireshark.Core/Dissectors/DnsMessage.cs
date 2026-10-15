using System.Text;

namespace MiniWireshark.Dissectors;

public readonly record struct DnsQuestion(string Name, ushort Type, ushort Class)
{
    public string TypeName => DnsMessage.TypeName(Type);
}

public readonly record struct DnsRecord(string Name, ushort Type, ushort Class, uint Ttl, string? Data)
{
    public string TypeName => DnsMessage.TypeName(Type);
}

/// <summary>
/// Dissection d'un message DNS (sur UDP port 53). Gere la compression de noms par pointeurs
/// (RFC 1035 4.1.4), avec protection anti-boucle. Interprete les enregistrements A/AAAA/CNAME ;
/// les autres types sont reconnus mais leur contenu n'est pas decode en detail.
/// </summary>
public sealed class DnsMessage
{
    public ushort Id { get; init; }
    public bool IsResponse { get; init; }
    public IReadOnlyList<DnsQuestion> Questions { get; init; } = Array.Empty<DnsQuestion>();
    public IReadOnlyList<DnsRecord> Answers { get; init; } = Array.Empty<DnsRecord>();

    public static string TypeName(ushort type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => type.ToString()
    };

    public static DnsMessage? Parse(byte[] buffer)
    {
        if (buffer.Length < 12)
            return null;

        ushort id = ReadUInt16(buffer, 0);
        ushort flags = ReadUInt16(buffer, 2);
        bool isResponse = (flags & 0x8000) != 0;
        ushort qdCount = ReadUInt16(buffer, 4);
        ushort anCount = ReadUInt16(buffer, 6);

        int offset = 12;

        var questions = new List<DnsQuestion>();
        for (int i = 0; i < qdCount && offset < buffer.Length; i++)
        {
            string name = ReadName(buffer, ref offset);
            if (offset + 4 > buffer.Length) break;
            ushort qtype = ReadUInt16(buffer, offset); offset += 2;
            ushort qclass = ReadUInt16(buffer, offset); offset += 2;
            questions.Add(new DnsQuestion(name, qtype, qclass));
        }

        var answers = new List<DnsRecord>();
        for (int i = 0; i < anCount && offset < buffer.Length; i++)
        {
            string name = ReadName(buffer, ref offset);
            if (offset + 10 > buffer.Length) break;
            ushort type = ReadUInt16(buffer, offset); offset += 2;
            ushort cls = ReadUInt16(buffer, offset); offset += 2;
            uint ttl = ReadUInt32(buffer, offset); offset += 4;
            ushort rdLength = ReadUInt16(buffer, offset); offset += 2;
            if (offset + rdLength > buffer.Length) break;

            string? data = type switch
            {
                1 when rdLength == 4 => new System.Net.IPAddress(buffer.AsSpan(offset, 4).ToArray()).ToString(),
                28 when rdLength == 16 => new System.Net.IPAddress(buffer.AsSpan(offset, 16).ToArray()).ToString(),
                5 => ReadNameAt(buffer, offset),
                _ => null
            };

            offset += rdLength; // on avance toujours de RDLENGTH, meme si on n'a pas interprete le contenu
            answers.Add(new DnsRecord(name, type, cls, ttl, data));
        }

        return new DnsMessage { Id = id, IsResponse = isResponse, Questions = questions, Answers = answers };
    }

    /// <summary>Lit un nom a une position donnee sans affecter la position de lecture principale (pour les RDATA).</summary>
    private static string ReadNameAt(byte[] buffer, int at)
    {
        int offset = at;
        return ReadName(buffer, ref offset);
    }

    /// <summary>
    /// Lit un nom DNS (suite de labels terminee par 0, ou pointeur de compression 0xC0xx).
    /// Avance <paramref name="offset"/> jusqu'apres le nom dans le flux principal (apres le premier
    /// pointeur rencontre, pas apres la cible du saut).
    /// </summary>
    private static string ReadName(byte[] buffer, ref int offset)
    {
        var labels = new List<string>();
        int pos = offset;
        bool jumped = false;
        int jumps = 0;

        while (pos < buffer.Length)
        {
            byte len = buffer[pos];

            if (len == 0)
            {
                pos++;
                if (!jumped) offset = pos;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= buffer.Length) break;
                int pointer = ((len & 0x3F) << 8) | buffer[pos + 1];
                if (!jumped) { offset = pos + 2; jumped = true; }
                if (++jumps > 10) break; // protection anti-boucle sur pointeurs malformes
                pos = pointer;
                continue;
            }

            pos++;
            if (pos + len > buffer.Length) break;
            labels.Add(Encoding.ASCII.GetString(buffer, pos, len));
            pos += len;
        }

        return labels.Count > 0 ? string.Join(".", labels) : "<root>";
    }

    private static ushort ReadUInt16(byte[] buffer, int offset) => (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

    private static uint ReadUInt32(byte[] buffer, int offset) =>
        ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) | ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];
}