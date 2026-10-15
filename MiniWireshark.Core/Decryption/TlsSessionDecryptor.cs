using System.Security.Cryptography;
using System.Text;
using MiniWireshark.Core.Streams;

namespace MiniWireshark.Core.Decryption;

public sealed record DecryptedTlsRecord(
    bool FromEndpointA,
    int PacketNumber,
    byte ContentType,
    bool WasEncrypted,
    byte[] Data,
    string Description);

public sealed class TlsDecryptionResult
{
    public string? Error { get; init; }
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();
    public string? CipherSuite { get; init; }
    public string? Alpn { get; init; }
    public IReadOnlyList<DecryptedTlsRecord> Records { get; init; } = Array.Empty<DecryptedTlsRecord>();
    public bool ClientIsEndpointA { get; init; }
    public bool Success => Error is null;

    public byte[] ApplicationData(bool fromClient)
    {
        bool fromEndpointA = fromClient == ClientIsEndpointA;

        return Records
            .Where(r => r.WasEncrypted && r.ContentType == 23 && r.FromEndpointA == fromEndpointA)
            .SelectMany(r => r.Data)
            .ToArray();
    }
}

public static class TlsSessionDecryptor
{
    private sealed class Context
    {
        public string? Alpn;
        public List<string> Notes { get; } = new();
    }

    public static TlsDecryptionResult Decrypt(TcpStream stream, KeyLog keyLog)
    {
        var dirA = TcpDirectionReassembler.Reassemble(stream, true);
        var dirB = TcpDirectionReassembler.Reassemble(stream, false);

        bool aIsClient;
        if (LooksLikeHandshake(dirA.Data, 0x01)) aIsClient = true;
        else if (LooksLikeHandshake(dirB.Data, 0x01)) aIsClient = false;
        else return Fail("ClientHello not found : Capture started before handshake or not a TLS session?");

        var client = aIsClient ? dirA : dirB;
        var server = aIsClient ? dirB : dirA;

        if (client.Data.Length < 43)
            return Fail("ClientHello too short : Capture started before handshake or not a TLS session?");
        
        if (!LooksLikeHandshake(client.Data, 0x02))
            return Fail("ClientHello not found : Capture started before handshake or not a TLS session?");

        if (!TryReadCipherSuite(server.Data, out ushort suiteId))
            return Fail("ServerHello unreadable");
        
          if (!Tls13CipherSuites.TryGet(suiteId, out var suite))
            return Fail($"Suite {Tls13CipherSuites.NameOf(suiteId)} non prise en charge : seul TLS 1.3 (AES-GCM, ChaCha20) est géré, pas TLS 1.2.");

        if (suite.IsChaCha && !ChaCha20Poly1305.IsSupported)
            return Fail("ChaCha20-Poly1305 n'est pas disponible sur cette plateforme.");
        
        byte[] clientRandom = client.Data.AsSpan(11, 32).ToArray();

        byte[]? clientHandshake = keyLog.Find(clientRandom, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        byte[]? serverHandshake = keyLog.Find(clientRandom, "SERVER_HANDSHAKE_TRAFFIC_SECRET");
        byte[]? clientApp = keyLog.Find(clientRandom, "CLIENT_TRAFFIC_SECRET_0");
        byte[]? serverApp = keyLog.Find(clientRandom, "SERVER_TRAFFIC_SECRET_0");

        if (clientHandshake is null && serverHandshake is null && clientApp is null && serverApp is null)
        {
            string shortId = Convert.ToHexString(clientRandom)[..8];
            return Fail($"Aucune clé pour cette connexion dans le fichier ({keyLog.EntryCount} lignes lues, client_random {shortId}…). " +
                        "Le navigateur a-t-il été lancé avec SSLKEYLOGFILE avant d'ouvrir cette connexion ?");
        }

        var context = new Context();
        var all = new List<(int Order, DecryptedTlsRecord Record)>();

        all.AddRange(DecryptDirection(client, aIsClient, suite, clientHandshake, clientApp, "client", context));
        all.AddRange(DecryptDirection(server, !aIsClient, suite, serverHandshake, serverApp, "server", context));

        if (client.HasGap)
            context.Notes.Add("Gaps in the client direction : some packets were not captured.");
        if (server.HasGap)
            context.Notes.Add("Gaps in the server direction : some packets were not captured.");

        var ordered = all
            .OrderBy(r => r.Record.PacketNumber)
            .ThenBy(r => r.Order)
            .Select(r => r.Record)
            .ToList();

        return new TlsDecryptionResult
        {
            CipherSuite = suite.Name,
            Alpn = context.Alpn,
            Records = ordered,
            Notes = context.Notes,
            ClientIsEndpointA = aIsClient
        };
    }

    private static List<(int Order, DecryptedTlsRecord Record)> DecryptDirection(
        TcpDirectionData direction,
        bool fromEndpointA,
        Tls13Suite suite,
        byte[]? handshakeSecret,
        byte[]? applicationSecret,
        string who,
        Context context)
    {
        var output = new List<(int, DecryptedTlsRecord)>();
        var data = direction.Data;

        var handshakeKeys = handshakeSecret is null ? null : new Tls13RecordKeys(suite, handshakeSecret);
        var applicationKeys = applicationSecret is null ? null : new Tls13RecordKeys(suite, applicationSecret);

        var current = handshakeKeys ?? applicationKeys;
        bool inApplicationPhase = handshakeKeys is null;

        int pos = 0;
        int order = 0;

        while (pos + 5 <= data.Length)
        {
            byte outerType = data[pos];
            int length = (data[pos + 3] << 8) | data[pos + 4];

            if (data[pos + 1] != 0x03 || pos + 5 + length > data.Length)
                break;

            int packet = direction.PacketNumberAt(pos + 5 + length - 1);
            var header = data.AsSpan(pos, 5);
            var payload = data.AsSpan(pos + 5, length);

            if (outerType == 23)
            {
                bool ok = false;
                byte innerType = 0;
                byte[] content = Array.Empty<byte>();

                if (current is not null)
                    ok = current.TryDecrypt(header, payload, out innerType, out content);
                
                if (!ok && !inApplicationPhase && applicationKeys is not null)
                {
                    ok = applicationKeys.TryDecrypt(header, payload, out innerType, out content);
                    if (ok)
                    {
                        current = applicationKeys;
                        inApplicationPhase = true;
                    }
                }

                if (!ok)
                {
                    context.Notes.Add($"Failed to decrypt {who} application data at packet {packet} (offset {pos})");
                    break;
                }

                string description = Describe(innerType, content, context, out bool containsFinished);

                if (!inApplicationPhase && containsFinished && applicationKeys is not null)
                {
                    current = applicationKeys;
                    inApplicationPhase = true;
                }

                output.Add((order++, new DecryptedTlsRecord(fromEndpointA, packet, innerType, true, content, description)));
            }
            else
            {
                var clearData = payload.ToArray();
                string description = outerType switch
                {
                    20 => "ChangeCipherSpec",
                    21 => "Alert",
                    22 => "Handshake : " + DescribeHandshakeMessages(clearData, out _, context),
                    _ => $"Unknown ({outerType})"
                };

                output.Add((order++, new DecryptedTlsRecord(fromEndpointA, packet, outerType, false, clearData, description)));
            }
            pos += 5 + length;
        }
        return output;
    }

     private static string Describe(byte innerType, byte[] content, Context context, out bool containsFinished)
    {
        containsFinished = false;

        switch (innerType)
        {
            case 22:
                return "Handshake : " + DescribeHandshakeMessages(content, out containsFinished, context);
            case 21:
                return content.Length >= 2 ? $"Alert : {AlertName(content[1])}" : "Alert";
            case 23:
                return $"Application Data ({content.Length} octets)";
            default:
                return $"Contenu de type {innerType}";
        }
    }

    private static string AlertName(byte code) => code switch
    {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        48 => "unknown_ca",
        70 => "protocol_version",
        80 => "internal_error",
        90 => "user_canceled",
        _ => $"alerte {code}"
    };

    /// <summary>Liste les messages d'un enregistrement Handshake ; releve au passage l'ALPN dans EncryptedExtensions.</summary>
    private static string DescribeHandshakeMessages(byte[] data, out bool containsFinished, Context context)
    {
        containsFinished = false;
        var names = new List<string>();
        int pos = 0;

        while (pos + 4 <= data.Length)
        {
            int type = data[pos];
            int length = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];

            names.Add(HandshakeName(type));

            if (type == 20)
                containsFinished = true;

            if (type == 8 && context.Alpn is null && pos + 4 + length <= data.Length)
                context.Alpn = ReadAlpn(data.AsSpan(pos + 4, length));

            pos += 4 + length;
        }

        return names.Count > 0 ? string.Join(", ", names) : "Handshake";
    }

    private static string HandshakeName(int type) => type switch
    {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End Of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        13 => "Certificate Request",
        15 => "Certificate Verify",
        20 => "Finished",
        24 => "Key Update",
        _ => $"Handshake (type {type})"
    };

    /// <summary>EncryptedExtensions = [taille:2][extensions...], chaque extension = [type:2][taille:2][donnees]. ALPN = type 16.</summary>
    private static string? ReadAlpn(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return null;

        int end = Math.Min(body.Length, 2 + ((body[0] << 8) | body[1]));
        int pos = 2;

        while (pos + 4 <= end)
        {
            int type = (body[pos] << 8) | body[pos + 1];
            int length = (body[pos + 2] << 8) | body[pos + 3];
            pos += 4;

            if (pos + length > end)
                return null;

            if (type == 0x0010)
            {
                // donnees = [taille de liste:2][taille du protocole:1][protocole]
                var ext = body.Slice(pos, length);
                if (ext.Length >= 3 && 3 + ext[2] <= ext.Length)
                    return Encoding.ASCII.GetString(ext.Slice(3, ext[2]));
                return null;
            }

            pos += length;
        }

        return null;
    }

    private static bool LooksLikeHandshake(byte[] data, byte handshakeType) =>
        data.Length >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == handshakeType;

    /// <summary>ServerHello : record(5) + handshake(4) + version(2) + random(32) + session_id(1+n) + cipher_suite(2).</summary>
    private static bool TryReadCipherSuite(byte[] data, out ushort suite)
    {
        suite = 0;
        if (data.Length < 44)
            return false;

        int pos = 43;
        int sessionIdLength = data[pos++];
        pos += sessionIdLength;

        if (pos + 2 > data.Length)
            return false;

        suite = (ushort)((data[pos] << 8) | data[pos + 1]);
        return true;
    }

    private static TlsDecryptionResult Fail(string message) => new() { Error = message };
}
