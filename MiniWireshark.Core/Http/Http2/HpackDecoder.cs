using System.Text;

namespace MiniWireshark.Core.Http.Http2;

/// <summary>
/// Decodeur HPACK (RFC 7541) : compression des en-tetes HTTP/2. Il est a etat : la table dynamique evolue avec
/// chaque bloc d'en-tetes, il faut donc un decodeur par sens de la connexion et lui presenter les blocs dans l'ordre.
/// </summary>
internal sealed class HpackDecoder
{
    // Table statique (RFC 7541, annexe A) : les indices 1 a 61.
    private static readonly (string Name, string Value)[] StaticTable =
    {
        (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"),
        (":scheme", "http"), (":scheme", "https"), (":status", "200"), (":status", "204"), (":status", "206"),
        (":status", "304"), (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
        ("access-control-allow-origin", ""), ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
        ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
        ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
        ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""),
        ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
        ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
        ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""),
        ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
        ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", "")
    };

    // Plafond de securite pour la taille de la table dynamique (le pair annonce 4096 par defaut, Chrome 65536).
    private const int MaxAllowedTableSize = 1 << 20;

    // Table dynamique : l'entree la plus recente est en tete (indice 62 dans l'espace d'adressage HPACK).
    private readonly List<(string Name, string Value)> _dynamic = new();
    private int _dynamicSize;
    private int _maxDynamicSize = 4096;

    /// <summary>Decode un bloc d'en-tetes complet. Leve FormatException si le bloc est invalide ou desynchronise.</summary>
    public List<(string Name, string Value)> Decode(ReadOnlySpan<byte> block)
    {
        var headers = new List<(string, string)>();
        int pos = 0;

        while (pos < block.Length)
        {
            byte first = block[pos];

            if ((first & 0x80) != 0)
            {
                // Champ indexe : [1][index:7]
                int index = ReadInteger(block, ref pos, 7);
                headers.Add(Lookup(index));
            }
            else if ((first & 0xC0) == 0x40)
            {
                // Litteral avec indexation : [01][index du nom:6] ; ajoute a la table dynamique
                var header = ReadLiteral(block, ref pos, 6);
                headers.Add(header);
                AddToDynamicTable(header);
            }
            else if ((first & 0xE0) == 0x20)
            {
                // Mise a jour de la taille de la table dynamique : [001][taille:5]
                int newSize = ReadInteger(block, ref pos, 5);
                if (newSize > MaxAllowedTableSize)
                    throw new FormatException("Taille de table dynamique HPACK excessive.");
                _maxDynamicSize = newSize;
                Evict();
            }
            else
            {
                // Litteral sans indexation [0000] ou jamais indexe [0001] : [index du nom:4]
                headers.Add(ReadLiteral(block, ref pos, 4));
            }
        }

        return headers;
    }

    private (string Name, string Value) Lookup(int index)
    {
        if (index == 0)
            throw new FormatException("Index HPACK 0 invalide.");

        if (index <= StaticTable.Length)
            return StaticTable[index - 1];

        int dynamicIndex = index - StaticTable.Length - 1;
        if (dynamicIndex >= _dynamic.Count)
            throw new FormatException("Index HPACK hors de la table dynamique (flux desynchronise ?).");

        return _dynamic[dynamicIndex];
    }

    private (string Name, string Value) ReadLiteral(ReadOnlySpan<byte> block, ref int pos, int prefixBits)
    {
        int nameIndex = ReadInteger(block, ref pos, prefixBits);
        string name = nameIndex == 0 ? ReadString(block, ref pos) : Lookup(nameIndex).Name;
        string value = ReadString(block, ref pos);
        return (name, value);
    }

    /// <summary>Entier a prefixe de N bits (RFC 7541 §5.1) : si les N bits sont tous a 1, la suite est en base 128.</summary>
    private static int ReadInteger(ReadOnlySpan<byte> data, ref int pos, int prefixBits)
    {
        if (pos >= data.Length)
            throw new FormatException("Entier HPACK tronque.");

        int mask = (1 << prefixBits) - 1;
        int value = data[pos++] & mask;
        if (value < mask)
            return value;

        int shift = 0;
        while (true)
        {
            if (pos >= data.Length)
                throw new FormatException("Entier HPACK tronque.");
            if (shift > 28)
                throw new FormatException("Entier HPACK trop grand.");

            byte b = data[pos++];
            value += (b & 0x7F) << shift;
            shift += 7;

            if ((b & 0x80) == 0)
                return value;
        }
    }

    /// <summary>Chaine HPACK (RFC 7541 §5.2) : [H:1][longueur:7] puis les octets, en Huffman si H = 1.</summary>
    private static string ReadString(ReadOnlySpan<byte> data, ref int pos)
    {
        if (pos >= data.Length)
            throw new FormatException("Chaine HPACK tronquee.");

        bool huffman = (data[pos] & 0x80) != 0;
        int length = ReadInteger(data, ref pos, 7);

        if (length < 0 || pos + length > data.Length)
            throw new FormatException("Chaine HPACK tronquee.");

        var raw = data.Slice(pos, length);
        pos += length;

        // Latin1 : un caractere = un octet, ce qui rend le calcul de taille de la table exact (RFC 7541 §4.1).
        return Encoding.Latin1.GetString(huffman ? HpackHuffman.Decode(raw) : raw.ToArray());
    }

    private void AddToDynamicTable((string Name, string Value) header)
    {
        int size = header.Name.Length + header.Value.Length + 32;

        // Une entree plus grande que la table vide celle-ci, sans etre ajoutee (RFC 7541 §4.4).
        if (size > _maxDynamicSize)
        {
            _dynamic.Clear();
            _dynamicSize = 0;
            return;
        }

        _dynamic.Insert(0, header);
        _dynamicSize += size;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicSize > _maxDynamicSize && _dynamic.Count > 0)
        {
            var last = _dynamic[^1];
            _dynamicSize -= last.Name.Length + last.Value.Length + 32;
            _dynamic.RemoveAt(_dynamic.Count - 1);
        }
    }
}