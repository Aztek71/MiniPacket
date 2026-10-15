using System.Globalization;
using System.Text;

namespace MiniWireshark.Core.Http;

/// <summary>
/// Decode une connexion HTTP/1.x a partir des octets applicatifs de chaque sens (dechiffres, ou en clair) :
/// lignes de depart, en-tetes, corps delimites par Content-Length, par Transfer-Encoding: chunked, ou par la
/// fermeture de la connexion. Gere le pipelining (plusieurs requetes d'affilee), HEAD, 204/304 et les reponses 1xx.
/// </summary>
public static class Http1Decoder
{
    private static readonly string[] MethodPrefixes =
        { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " };

    /// <summary>Vrai si les octets du client commencent comme une requete HTTP/1.x (methode + espace).</summary>
    public static bool LooksLikeHttp1(byte[] clientData)
    {
        foreach (string prefix in MethodPrefixes)
        {
            if (clientData.Length >= prefix.Length && Encoding.ASCII.GetString(clientData, 0, prefix.Length) == prefix)
                return true;
        }
        return false;
    }

    public static HttpConversation Decode(byte[] clientData, byte[] serverData)
    {
        var problems = new List<string>();
        var events = new List<string>();
        var all = new List<HttpMessage>();

        var methods = ParseRequests(clientData, problems, all);
        ParseResponses(serverData, methods, problems, events, all);

        var ordered = all
            .Select((message, index) => (message, index))
            .OrderBy(x => x.message.StreamId ?? 0)
            .ThenByDescending(x => x.message.FromClient)   // la requete avant sa reponse
            .ThenBy(x => x.index)
            .Select(x => x.message)
            .ToList();

        return new HttpConversation { Messages = ordered, ConnectionEvents = events, Problems = problems };
    }

    /// <summary>Lit toutes les requetes du client dans l'ordre ; renvoie leurs methodes (utiles pour interpreter les reponses).</summary>
    private static List<string> ParseRequests(byte[] data, List<string> problems, List<HttpMessage> all)
    {
        var methods = new List<string>();
        var reader = new Reader(data);
        int exchange = 0;

        while (reader.Remaining > 0)
        {
            if (!reader.TryReadLine(out string line))
            {
                problems.Add("Requête incomplète en fin de capture.");
                break;
            }

            if (line.Length == 0)
                continue;   // CRLF superflu entre deux messages

            var parts = line.Split(' ');
            if (parts.Length < 3 || !parts[^1].StartsWith("HTTP/", StringComparison.Ordinal))
            {
                problems.Add($"Ligne de requête illisible (flux désynchronisé ou autre protocole) : « {Truncate(line)} ».");
                break;
            }

            exchange++;
            methods.Add(parts[0]);
            var message = new HttpMessage { StreamId = exchange, FromClient = true, StartLine = line };
            all.Add(message);

            if (!ReadHeaders(reader, message.Headers))
            {
                problems.Add($"En-têtes de la requête {exchange} incomplets en fin de capture.");
                Finish(message, new List<byte>(), complete: false);
                break;
            }

            ReadBody(reader, message, untilCloseIfUnbounded: false);
        }

        return methods;
    }

    private static void ParseResponses(byte[] data, List<string> requestMethods, List<string> problems, List<string> events, List<HttpMessage> all)
    {
        var reader = new Reader(data);
        int exchange = 0;   // nombre de reponses finales deja lues = index de la requete correspondante

        while (reader.Remaining > 0)
        {
            if (!reader.TryReadLine(out string line))
            {
                problems.Add("Réponse incomplète en fin de capture.");
                break;
            }

            if (line.Length == 0)
                continue;

            var parts = line.Split(' ', 3);
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.Ordinal)
                || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int status))
            {
                problems.Add($"Ligne de réponse illisible (flux désynchronisé ou autre protocole) : « {Truncate(line)} ».");
                break;
            }

            var message = new HttpMessage { StreamId = exchange + 1, FromClient = false, StartLine = line };
            all.Add(message);

            if (!ReadHeaders(reader, message.Headers))
            {
                problems.Add($"En-têtes de la réponse {exchange + 1} incomplets en fin de capture.");
                Finish(message, new List<byte>(), complete: false);
                break;
            }

            // 1xx : reponse intermediaire (100 Continue, 103 Early Hints), la vraie reponse suit.
            if (status is >= 100 and < 200)
            {
                Finish(message, new List<byte>(), complete: true);
                if (status == 101)
                {
                    events.Add("101 Switching Protocols : la suite de l'échange n'est plus du HTTP (WebSocket ?).");
                    break;
                }
                continue;
            }

            if (exchange >= requestMethods.Count)
                problems.Add($"Réponse {exchange + 1} sans requête correspondante dans la capture.");

            string method = exchange < requestMethods.Count ? requestMethods[exchange] : "GET";
            exchange++;

            bool tunnel = method == "CONNECT" && status is >= 200 and < 300;
            bool noBody = method == "HEAD" || status == 204 || status == 304 || tunnel;

            if (noBody)
            {
                Finish(message, new List<byte>(), complete: true);
                if (tunnel)
                {
                    events.Add("CONNECT accepté : la suite est un tunnel, pas du HTTP.");
                    break;
                }
                continue;
            }

            ReadBody(reader, message, untilCloseIfUnbounded: true);
        }
    }

    private static bool ReadHeaders(Reader reader, List<(string Name, string Value)> headers)
    {
        while (true)
        {
            if (!reader.TryReadLine(out string line))
                return false;
            if (line.Length == 0)
                return true;
            AddHeader(headers, line);
        }
    }

    private static void AddHeader(List<(string Name, string Value)> headers, string line)
    {
        int colon = line.IndexOf(':');
        if (colon <= 0)
            return;

        headers.Add((line[..colon].Trim(), HttpText.FixEncoding(line[(colon + 1)..].Trim())));
    }

    /// <summary>
    /// Lit le corps selon Transfer-Encoding, puis Content-Length. Sans l'un ni l'autre : pas de corps pour une
    /// requete, mais pour une reponse le corps s'etend jusqu'a la fermeture de la connexion.
    /// </summary>
    private static void ReadBody(Reader reader, HttpMessage message, bool untilCloseIfUnbounded)
    {
        var wire = new List<byte>();
        bool complete;

        string? transferEncoding = message.Header("transfer-encoding");
        string? contentLength = message.Header("content-length");

        if (transferEncoding != null && transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            complete = ReadChunked(reader, wire, message.Trailers);
        }
        else if (contentLength != null && int.TryParse(contentLength.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int length))
        {
            int available = Math.Min(length, reader.Remaining);
            wire.AddRange(reader.Take(available));
            complete = available == length;
        }
        else if (untilCloseIfUnbounded)
        {
            wire.AddRange(reader.Take(reader.Remaining));
            complete = true;
        }
        else
        {
            complete = true;
        }

        Finish(message, wire, complete);
    }

    /// <summary>Corps "chunked" : [taille en hexa][CRLF][donnees][CRLF] ..., puis un bloc de taille 0 et d'eventuels trailers.</summary>
    private static bool ReadChunked(Reader reader, List<byte> body, List<(string Name, string Value)> trailers)
    {
        while (true)
        {
            if (!reader.TryReadLine(out string sizeLine))
                return false;

            string hex = sizeLine.Split(';')[0].Trim();   // les extensions de chunk (";...") sont ignorees
            if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size < 0)
                return false;

            if (size == 0)
            {
                while (true)
                {
                    if (!reader.TryReadLine(out string trailerLine))
                        return false;
                    if (trailerLine.Length == 0)
                        return true;
                    AddHeader(trailers, trailerLine);
                }
            }

            int available = Math.Min(size, reader.Remaining);
            body.AddRange(reader.Take(available));
            if (available < size)
                return false;

            if (!reader.TryReadLine(out _))   // CRLF qui suit les donnees du chunk
                return false;
        }
    }

    private static void Finish(HttpMessage message, List<byte> wire, bool complete)
    {
        byte[] wireBytes = wire.ToArray();
        message.WireBodyLength = wireBytes.Length;
        message.Body = HttpBodyDecoder.Decode(wireBytes, message.Header("content-encoding"), out string? note);
        message.BodyNote = note;
        message.EndedStream = complete;
    }

    private static string Truncate(string text) => text.Length <= 60 ? text : text[..60] + "…";

    /// <summary>Lecteur sequentiel sur un tampon : lit ligne par ligne (CRLF ou LF) ou par blocs d'octets.</summary>
    private sealed class Reader
    {
        private readonly byte[] _data;
        private int _pos;

        public Reader(byte[] data) => _data = data;

        public int Remaining => _data.Length - _pos;

        /// <summary>Lit une ligne complete. Renvoie false (sans rien consommer) si la fin de ligne n'est pas encore arrivee.</summary>
        public bool TryReadLine(out string line)
        {
            for (int i = _pos; i < _data.Length; i++)
            {
                if (_data[i] != (byte)'\n')
                    continue;

                int end = i > _pos && _data[i - 1] == (byte)'\r' ? i - 1 : i;
                line = Encoding.Latin1.GetString(_data, _pos, end - _pos);
                _pos = i + 1;
                return true;
            }

            line = string.Empty;
            return false;
        }

        public byte[] Take(int count)
        {
            var bytes = _data.AsSpan(_pos, count).ToArray();
            _pos += count;
            return bytes;
        }
    }
}