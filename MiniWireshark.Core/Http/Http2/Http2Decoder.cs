using System.Text;

namespace MiniWireshark.Core.Http.Http2;

public sealed class Http2Conversation : HttpConversation
{
    /// <summary>Requetes et reponses, regroupees par flux (la requete avant sa reponse).</summary>
    public new IReadOnlyList<HttpMessage> Messages { get; init; } = Array.Empty<HttpMessage>();

    /// <summary>Trames de controle de la connexion : SETTINGS, PING, GOAWAY, RST_STREAM.</summary>
    public new IReadOnlyList<string> ConnectionEvents { get; init; } = Array.Empty<string>();

    /// <summary>Anomalies rencontrees (trame tronquee, HPACK illisible...).</summary>
    public new IReadOnlyList<string> Problems { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Decode une connexion HTTP/2 a partir des octets applicatifs (deja dechiffres) de chaque sens :
/// trames (RFC 9113), en-tetes HPACK (RFC 7541), regroupement par flux et decompression des corps.
/// </summary>
public static class Http2Decoder
{
    private static readonly byte[] ClientPreface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    // Types de trames
    private const byte Data = 0x0, Headers = 0x1, Priority = 0x2, RstStream = 0x3, Settings = 0x4,
        PushPromise = 0x5, Ping = 0x6, GoAway = 0x7, WindowUpdate = 0x8, Continuation = 0x9;

    // Drapeaux
    private const byte EndStream = 0x1, EndHeaders = 0x4, Padded = 0x8, PriorityFlag = 0x20, Ack = 0x1;

    private sealed class State
    {
        public Dictionary<(int StreamId, bool IsRequest), HttpMessage> Active { get; } = new();
        public List<HttpMessage> All { get; } = new();
        public Dictionary<HttpMessage, List<byte>> WireBodies { get; } = new();
        public List<string> Events { get; } = new();
        public List<string> Problems { get; } = new();
    }

    /// <param name="clientData">Octets applicatifs envoyes par le client (prefaces et trames).</param>
    /// <param name="serverData">Octets applicatifs envoyes par le serveur.</param>
    public static Http2Conversation Decode(byte[] clientData, byte[] serverData)
    {
        var state = new State();

        // Chaque sens a son propre contexte HPACK : on peut donc les decoder separement.
        ParseDirection(clientData, fromClient: true, state);
        ParseDirection(serverData, fromClient: false, state);

        foreach (var message in state.All)
        {
            byte[] wire = state.WireBodies[message].ToArray();
            message.WireBodyLength = wire.Length;
            message.Body = HttpBodyDecoder.Decode(wire, message.Header("content-encoding"), out string? note);
            message.BodyNote = note;
        }

        var ordered = state.All
            .Select((message, index) => (message, index))
            .OrderBy(x => x.message.StreamId ?? 0)
            .ThenByDescending(x => x.message.FromClient)   // la requete avant sa reponse
            .ThenBy(x => x.index)
            .Select(x => x.message)
            .ToList();

        return new Http2Conversation { Messages = ordered, ConnectionEvents = state.Events, Problems = state.Problems };
    }

    private static void ParseDirection(byte[] data, bool fromClient, State state)
    {
        string side = fromClient ? "client" : "serveur";
        var hpack = new HpackDecoder();
        bool hpackBroken = false;
        int pos = 0;

        if (fromClient)
        {
            if (data.AsSpan().StartsWith(ClientPreface))
            {
                pos = ClientPreface.Length;
            }
            else
            {
                state.Problems.Add("Préface HTTP/2 absente côté client : ce flux n'est pas du HTTP/2 ou la capture est incomplète.");
                return;
            }
        }

        // Bloc d'en-tetes en cours d'assemblage : HEADERS ou PUSH_PROMISE, suivi de CONTINUATION jusqu'a END_HEADERS.
        var block = new List<byte>();
        bool assembling = false;
        int blockStream = 0;
        int blockPromised = 0;
        bool blockEndStream = false;

        while (pos + 9 <= data.Length)
        {
            int length = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
            byte type = data[pos + 3];
            byte flags = data[pos + 4];
            int streamId = (int)(((uint)data[pos + 5] << 24 | (uint)data[pos + 6] << 16 | (uint)data[pos + 7] << 8 | data[pos + 8]) & 0x7FFFFFFF);

            if (pos + 9 + length > data.Length)
            {
                state.Problems.Add($"Trame incomplète côté {side} en fin de capture (type {type}, {length} octets annoncés).");
                break;
            }

            var payload = data.AsSpan(pos + 9, length);
            pos += 9 + length;

            if (assembling && type != Continuation)
            {
                state.Problems.Add($"Bloc d'en-têtes interrompu côté {side} (CONTINUATION attendue) : flux {blockStream}.");
                assembling = false;
                block.Clear();
            }

            switch (type)
            {
                case Data:
                {
                    if (!TryStripPadding(payload, (flags & Padded) != 0, 0, out var body))
                    {
                        state.Problems.Add($"Trame DATA invalide côté {side} (flux {streamId}).");
                        break;
                    }

                    var message = FindOrCreateMessage(state, streamId, fromClient);
                    state.WireBodies[message].AddRange(body.ToArray());
                    if ((flags & EndStream) != 0)
                        message.EndedStream = true;
                    break;
                }

                case Headers:
                {
                    int prefix = (flags & PriorityFlag) != 0 ? 5 : 0;
                    if (!TryStripPadding(payload, (flags & Padded) != 0, prefix, out var fragment))
                    {
                        state.Problems.Add($"Trame HEADERS invalide côté {side} (flux {streamId}).");
                        break;
                    }

                    block.Clear();
                    block.AddRange(fragment.ToArray());
                    blockStream = streamId;
                    blockPromised = 0;
                    blockEndStream = (flags & EndStream) != 0;

                    if ((flags & EndHeaders) != 0)
                        FinishHeaderBlock(state, hpack, ref hpackBroken, side, block, blockStream, blockPromised, blockEndStream, fromClient);
                    else
                        assembling = true;
                    break;
                }

                case PushPromise:
                {
                    // [pad:1?][identifiant du flux promis:4][fragment]
                    if (!TryStripPadding(payload, (flags & Padded) != 0, 4, out var fragment) || payload.Length < 4)
                    {
                        state.Problems.Add($"Trame PUSH_PROMISE invalide côté {side}.");
                        break;
                    }

                    int promisedOffset = (flags & Padded) != 0 ? 1 : 0;
                    int promised = (int)(((uint)payload[promisedOffset] << 24 | (uint)payload[promisedOffset + 1] << 16
                                          | (uint)payload[promisedOffset + 2] << 8 | payload[promisedOffset + 3]) & 0x7FFFFFFF);

                    block.Clear();
                    block.AddRange(fragment.ToArray());
                    blockStream = streamId;
                    blockPromised = promised;
                    blockEndStream = false;

                    if ((flags & EndHeaders) != 0)
                        FinishHeaderBlock(state, hpack, ref hpackBroken, side, block, blockStream, blockPromised, blockEndStream, fromClient);
                    else
                        assembling = true;
                    break;
                }

                case Continuation:
                {
                    if (!assembling || streamId != blockStream)
                    {
                        state.Problems.Add($"CONTINUATION inattendue côté {side} (flux {streamId}).");
                        break;
                    }

                    block.AddRange(payload.ToArray());

                    if ((flags & EndHeaders) != 0)
                    {
                        assembling = false;
                        FinishHeaderBlock(state, hpack, ref hpackBroken, side, block, blockStream, blockPromised, blockEndStream, fromClient);
                    }
                    break;
                }

                case Settings:
                    state.Events.Add((flags & Ack) != 0
                        ? $"{side} → SETTINGS (accusé de réception)"
                        : $"{side} → SETTINGS : {DescribeSettings(payload)}");
                    break;

                case RstStream:
                    state.Events.Add(payload.Length >= 4
                        ? $"{side} → RST_STREAM sur le flux {streamId} : {ErrorName(ReadUInt32(payload, 0))}"
                        : $"{side} → RST_STREAM sur le flux {streamId}");
                    break;

                case Ping:
                    state.Events.Add($"{side} → PING" + ((flags & Ack) != 0 ? " (réponse)" : string.Empty));
                    break;

                case GoAway:
                    if (payload.Length >= 8)
                        state.Events.Add($"{side} → GOAWAY : dernier flux traité {ReadUInt32(payload, 0) & 0x7FFFFFFF}, {ErrorName(ReadUInt32(payload, 4))}");
                    else
                        state.Events.Add($"{side} → GOAWAY");
                    break;

                case Priority:
                case WindowUpdate:
                    break;   // trames de controle de flux, sans interet pour la lecture

                default:
                    state.Events.Add($"{side} → trame de type {type} ({length} octets)");
                    break;
            }
        }
    }

    private static void FinishHeaderBlock(
        State state, HpackDecoder hpack, ref bool hpackBroken, string side,
        List<byte> block, int streamId, int promisedStreamId, bool endStream, bool fromClient)
    {
        // Une fois HPACK desynchronise (bloc perdu ou illisible), tous les suivants seraient faux : on s'arrete la.
        if (hpackBroken)
            return;

        List<(string Name, string Value)> headers;
        try
        {
            headers = hpack.Decode(block.ToArray());
        }
        catch (FormatException ex)
        {
            hpackBroken = true;
            state.Problems.Add($"En-têtes HPACK illisibles côté {side} (flux {streamId}) : {ex.Message} Les en-têtes suivants de ce sens sont ignorés.");
            return;
        }
        finally
        {
            block.Clear();
        }

        if (promisedStreamId != 0)
        {
            // PUSH_PROMISE : le serveur annonce la requete qu'il "simule" pour le flux promis.
            RegisterHeaders(state, promisedStreamId, isRequest: true, headers, endStream: false);
            return;
        }

        RegisterHeaders(state, streamId, isRequest: fromClient, headers, endStream);
    }

    private static void RegisterHeaders(State state, int streamId, bool isRequest, List<(string Name, string Value)> headers, bool endStream)
    {
        var key = (streamId, isRequest);

        if (!state.Active.TryGetValue(key, out var message))
        {
            // 1xx informatif (100 Continue, 103 Early Hints) : message a part, la vraie reponse viendra apres.
            string? status = headers.FirstOrDefault(h => h.Name == ":status").Value;
            if (!isRequest && status is { Length: 3 } && status[0] == '1' && status != "101")
            {
                var informational = CreateMessage(state, streamId, isRequest, headers);
                informational.EndedStream = true;
                return;
            }

            message = CreateMessage(state, streamId, isRequest, headers);
            state.Active[key] = message;
        }
        else
        {
            // Un second bloc d'en-tetes sur le meme flux et le meme sens = trailers.
            foreach (var (name, value) in headers)
                message.Trailers.Add((name, FixEncoding(value)));
        }

        if (endStream)
            message.EndedStream = true;
    }

    private static HttpMessage CreateMessage(State state, int streamId, bool isRequest, List<(string Name, string Value)> headers)
    {
        var message = new HttpMessage { StreamId = streamId, FromClient = isRequest };

        foreach (var (name, value) in headers)
            message.Headers.Add((name, FixEncoding(value)));

        message.StartLine = isRequest ? BuildRequestLine(message) : $"HTTP/2 {message.Header(":status") ?? "?"}";

        state.All.Add(message);
        state.WireBodies[message] = new List<byte>();
        return message;
    }

    /// <summary>DATA recu sans en-tetes lisibles (HPACK casse ou capture partielle) : on garde quand meme les octets.</summary>
    private static HttpMessage FindOrCreateMessage(State state, int streamId, bool isRequest)
    {
        if (state.Active.TryGetValue((streamId, isRequest), out var existing))
            return existing;

        var message = new HttpMessage
        {
            StreamId = streamId,
            FromClient = isRequest,
            StartLine = isRequest ? "(requête dont les en-têtes sont illisibles)" : "(réponse dont les en-têtes sont illisibles)"
        };

        state.Active[(streamId, isRequest)] = message;
        state.All.Add(message);
        state.WireBodies[message] = new List<byte>();
        return message;
    }

    private static string BuildRequestLine(HttpMessage message)
    {
        string method = message.Header(":method") ?? "?";
        string? scheme = message.Header(":scheme");
        string? authority = message.Header(":authority");
        string path = message.Header(":path") ?? "";

        return authority is null
            ? $"{method} {path}"
            : $"{method} {scheme ?? "https"}://{authority}{path}";
    }

    /// <summary>
    /// Retire le remplissage eventuel : [longueur du remplissage:1 si PADDED][prefixe fixe][contenu][remplissage].
    /// <paramref name="fixedPrefix"/> = octets a sauter apres l'octet de remplissage (priorite, id du flux promis...).
    /// </summary>
    private static bool TryStripPadding(ReadOnlySpan<byte> payload, bool padded, int fixedPrefix, out ReadOnlySpan<byte> content)
    {
        content = default;
        int offset = 0;
        int padding = 0;

        if (padded)
        {
            if (payload.Length < 1)
                return false;
            padding = payload[0];
            offset = 1;
        }

        int start = offset + fixedPrefix;
        int length = payload.Length - start - padding;
        if (length < 0)
            return false;

        content = payload.Slice(start, length);
        return true;
    }

    private static string DescribeSettings(ReadOnlySpan<byte> payload)
    {
        var parts = new List<string>();
        for (int i = 0; i + 6 <= payload.Length; i += 6)
        {
            int id = (payload[i] << 8) | payload[i + 1];
            uint value = ReadUInt32(payload, i + 2);
            string name = id switch
            {
                1 => "HEADER_TABLE_SIZE",
                2 => "ENABLE_PUSH",
                3 => "MAX_CONCURRENT_STREAMS",
                4 => "INITIAL_WINDOW_SIZE",
                5 => "MAX_FRAME_SIZE",
                6 => "MAX_HEADER_LIST_SIZE",
                _ => $"paramètre {id}"
            };
            parts.Add($"{name}={value}");
        }
        return parts.Count > 0 ? string.Join(", ", parts) : "(vide)";
    }

    private static string ErrorName(uint code) => code switch
    {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        4 => "SETTINGS_TIMEOUT",
        5 => "STREAM_CLOSED",
        6 => "FRAME_SIZE_ERROR",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        9 => "COMPRESSION_ERROR",
        _ => $"erreur {code}"
    };

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        (uint)data[offset] << 24 | (uint)data[offset + 1] << 16 | (uint)data[offset + 2] << 8 | data[offset + 3];

    /// <summary>
    /// HPACK nous donne des octets lus en Latin1. En-tetes de reponse et cookies contiennent parfois de l'UTF-8 :
    /// si les octets forment de l'UTF-8 valide, on affiche ce texte, sinon on garde tel quel.
    /// </summary>
    private static string FixEncoding(string latin1)
    {
        bool ascii = true;
        foreach (char c in latin1)
        {
            if (c >= 0x80)
            {
                ascii = false;
                break;
            }
        }

        if (ascii)
            return latin1;

        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(Encoding.Latin1.GetBytes(latin1));
        }
        catch (DecoderFallbackException)
        {
            return latin1;
        }
    }
}