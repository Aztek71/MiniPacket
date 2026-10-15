using System.Text;

namespace MiniWireshark.Dissectors;

/// <summary>
/// Dissection minimale d'un TLS ClientHello pour en extraire le SNI (Server Name Indication),
/// le nom de domaine demande, transmis en clair meme en HTTPS. Aucun dechiffrement.
/// Tolerant aux messages tronques : si le ClientHello est coupe (Chrome en envoie souvent de tres gros,
/// repartis sur plusieurs segments TCP), on renvoie ce qui a pu etre lu, SNI a null si non atteint.
/// Format : [Record: 0x16, version:2, length:2][Handshake: 0x01, length:3][version:2][random:32]
///          [session_id][cipher_suites][compression][extensions...]
/// </summary>
public sealed class TlsClientHello
{
    public string? ServerName { get; init; }

    public static TlsClientHello? Parse(ReadOnlySpan<byte> data)
    {
        // En-tete d'enregistrement TLS : type 0x16 (Handshake), version majeure 3 (SSL3 / TLS 1.x)
        if (data.Length < 6 || data[0] != 0x16 || data[1] != 0x03)
            return null;

        int pos = 5;

        if (!TryReadU8(data, ref pos, out int handshakeType) || handshakeType != 0x01) // 0x01 = ClientHello
            return null;

        // longueur du handshake (3) + client_version (2) + random (32)
        if (!TrySkip(data, ref pos, 3 + 2 + 32)) return new TlsClientHello();

        if (!TryReadU8(data, ref pos, out int sessionIdLen) || !TrySkip(data, ref pos, sessionIdLen)) return new TlsClientHello();
        if (!TryReadU16(data, ref pos, out int cipherLen) || !TrySkip(data, ref pos, cipherLen)) return new TlsClientHello();
        if (!TryReadU8(data, ref pos, out int compressionLen) || !TrySkip(data, ref pos, compressionLen)) return new TlsClientHello();
        if (!TryReadU16(data, ref pos, out int extensionsLen)) return new TlsClientHello();

        int extensionsEnd = Math.Min(data.Length, pos + extensionsLen);

        while (pos + 4 <= extensionsEnd)
        {
            TryReadU16(data, ref pos, out int extType);
            TryReadU16(data, ref pos, out int extLen);

            if (extType == 0x0000) // server_name
            {
                var name = ReadServerName(data.Slice(pos, Math.Min(extLen, data.Length - pos)));
                return new TlsClientHello { ServerName = name };
            }

            if (!TrySkip(data, ref pos, extLen))
                break;
        }

        return new TlsClientHello();
    }

    /// <summary>Format de l'extension : [liste:2] puis des entrees [type:1 (0 = hostname)][longueur:2][nom].</summary>
    private static string? ReadServerName(ReadOnlySpan<byte> ext)
    {
        int pos = 0;
        if (!TryReadU16(ext, ref pos, out _)) return null;

        while (pos + 3 <= ext.Length)
        {
            TryReadU8(ext, ref pos, out int nameType);
            TryReadU16(ext, ref pos, out int nameLen);

            if (pos + nameLen > ext.Length) return null;

            if (nameType == 0)
                return Encoding.ASCII.GetString(ext.Slice(pos, nameLen));

            pos += nameLen;
        }

        return null;
    }

    private static bool TryReadU8(ReadOnlySpan<byte> d, ref int pos, out int value)
    {
        if (pos + 1 > d.Length) { value = 0; return false; }
        value = d[pos++];
        return true;
    }

    private static bool TryReadU16(ReadOnlySpan<byte> d, ref int pos, out int value)
    {
        if (pos + 2 > d.Length) { value = 0; return false; }
        value = (d[pos] << 8) | d[pos + 1];
        pos += 2;
        return true;
    }

    private static bool TrySkip(ReadOnlySpan<byte> d, ref int pos, int count)
    {
        if (pos + count > d.Length) return false;
        pos += count;
        return true;
    }
}