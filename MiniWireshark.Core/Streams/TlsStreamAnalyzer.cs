using MiniWireshark.Dissectors;

namespace MiniWireshark.Core.Streams;

/// <summary>Un enregistrement TLS (ou un groupe d'enregistrements Application Data consecutifs) pret a afficher.</summary>
public sealed record TlsRecordSummary(
    bool FromEndpointA,
    string Description,
    int ByteCount,
    int RecordCount = 1,
    bool IsApplicationData = false);

public sealed record TlsStreamInfo(
    string? ServerName,
    IReadOnlyList<TlsRecordSummary> Records,
    long BytesFromA,
    long BytesFromB);

/// <summary>
/// Analyse un flux TCP reconstitue pour y reconnaitre une session TLS et en resumer les enregistrements
/// (Client Hello, Server Hello, Certificate, Application Data...). Aucun dechiffrement : on ne lit que
/// les en-tetes d'enregistrement, en clair, et les messages Handshake non chiffres.
/// </summary>
public static class TlsStreamAnalyzer
{
    private sealed class DirectionState
    {
        public List<byte> Buffer { get; } = new();
        public bool Encrypted { get; set; }   // vrai apres un Change Cipher Spec : les Handshake suivants sont chiffres
        public bool Desynced { get; set; }    // vrai si les en-tetes ne ressemblent plus a du TLS (segments manquants ?)
    }

    /// <summary>Renvoie null si le flux ne commence pas par un ClientHello TLS.</summary>
    public static TlsStreamInfo? Analyze(IReadOnlyList<TcpStreamDataChunk> chunks)
    {
        if (chunks.Count == 0)
            return null;

        // Un flux TLS commence par un enregistrement Handshake (0x16, version 3.x) contenant un ClientHello (0x01).
        var first = chunks[0].Data;
        if (first.Length < 6 || first[0] != 0x16 || first[1] != 0x03 || first[5] != 0x01)
            return null;

        // Les donnees sont deja fusionnees par sens : un ClientHello reparti sur plusieurs segments TCP est complet ici.
        string? serverName = TlsClientHello.Parse(first)?.ServerName;

        var states = new Dictionary<bool, DirectionState> { [true] = new(), [false] = new() };
        var records = new List<TlsRecordSummary>();
        long bytesA = 0, bytesB = 0;

        foreach (var chunk in chunks)
        {
            if (chunk.FromEndpointA) bytesA += chunk.Data.Length;
            else bytesB += chunk.Data.Length;

            var state = states[chunk.FromEndpointA];
            if (state.Desynced)
                continue;

            state.Buffer.AddRange(chunk.Data);
            ExtractRecords(state, chunk.FromEndpointA, records);
        }

        return new TlsStreamInfo(serverName, records, bytesA, bytesB);
    }

    /// <summary>Extrait les enregistrements complets du tampon ; garde les octets restants pour le prochain segment.</summary>
    private static void ExtractRecords(DirectionState state, bool fromA, List<TlsRecordSummary> records)
    {
        var buf = state.Buffer;
        int pos = 0;

        while (buf.Count - pos >= 5)
        {
            int type = buf[pos];
            int major = buf[pos + 1];
            int length = (buf[pos + 3] << 8) | buf[pos + 4];

            // 20 = Change Cipher Spec, 21 = Alert, 22 = Handshake, 23 = Application Data, 24 = Heartbeat
            if (type < 20 || type > 24 || major != 3)
            {
                state.Desynced = true;
                records.Add(new TlsRecordSummary(fromA, "Flux désynchronisé (segments manquants dans la capture ?)", 0));
                pos = buf.Count;
                break;
            }

            if (buf.Count - pos - 5 < length)
                break; // enregistrement incomplet : on attend la suite

            switch (type)
            {
                case 20:
                    records.Add(new TlsRecordSummary(fromA, "Change Cipher Spec", length));
                    state.Encrypted = true;
                    break;

                case 21:
                    records.Add(new TlsRecordSummary(fromA, state.Encrypted ? "Alert (chiffré)" : "Alert", length));
                    break;

                case 22:
                {
                    string description = state.Encrypted
                        ? "Handshake (chiffré)"
                        : DescribeHandshake(buf, pos + 5, length);
                    records.Add(new TlsRecordSummary(fromA, description, length));
                    break;
                }

                case 23:
                    AddApplicationData(records, fromA, length);
                    break;

                default:
                    records.Add(new TlsRecordSummary(fromA, "Heartbeat", length));
                    break;
            }

            pos += 5 + length;
        }

        buf.RemoveRange(0, pos);
    }

    /// <summary>Un enregistrement Handshake peut contenir plusieurs messages (ex: Server Hello + Certificate + Server Hello Done).</summary>
    private static string DescribeHandshake(List<byte> buf, int start, int length)
    {
        var names = new List<string>();
        int pos = start;
        int end = start + length;

        while (pos + 4 <= end)
        {
            int type = buf[pos];
            int messageLength = (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3];
            names.Add(HandshakeName(type));
            pos += 4 + messageLength;
        }

        return names.Count > 0 ? string.Join(", ", names) : "Handshake";
    }

    private static string HandshakeName(int type) => type switch
    {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Handshake (fragment)"
    };

    /// <summary>Les enregistrements Application Data consecutifs dans le meme sens sont fusionnes en une seule ligne.</summary>
    private static void AddApplicationData(List<TlsRecordSummary> records, bool fromA, int length)
    {
        if (records.Count > 0 && records[^1] is { IsApplicationData: true } last && last.FromEndpointA == fromA)
        {
            int count = last.RecordCount + 1;
            int bytes = last.ByteCount + length;
            records[^1] = last with
            {
                Description = AppDataDescription(count, bytes),
                ByteCount = bytes,
                RecordCount = count
            };
            return;
        }

        records.Add(new TlsRecordSummary(fromA, AppDataDescription(1, length), length, 1, true));
    }

    private static string AppDataDescription(int count, int bytes) =>
        $"Application Data (chiffré) : {count} enregistrement(s), {bytes} octets";
}