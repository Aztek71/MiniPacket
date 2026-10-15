using System.IO.Compression;

namespace MiniWireshark.Core.Http;

/// <summary>Decompresse un corps HTTP selon son en-tete Content-Encoding (gzip, deflate, br).</summary>
public static class HttpBodyDecoder
{
    // Garde-fou contre les "bombes de decompression" : on ne decompresse pas au-dela de cette taille.
    private const int MaxDecodedBytes = 4 * 1024 * 1024;

    public static byte[] Decode(byte[] wireBody, string? contentEncoding, out string? note)
    {
        note = null;

        if (wireBody.Length == 0 || string.IsNullOrWhiteSpace(contentEncoding))
            return wireBody;

        // "gzip, br" = gzip applique en premier : on decode dans l'ordre inverse.
        var encodings = contentEncoding
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.ToLowerInvariant())
            .Where(e => e != "identity")
            .Reverse()
            .ToList();

        byte[] data = wireBody;

        foreach (var encoding in encodings)
        {
            bool complete = true;
            byte[]? decoded = encoding switch
            {
                "gzip" or "x-gzip" => Inflate(data, s => new GZipStream(s, CompressionMode.Decompress), out complete),
                "br" => Inflate(data, s => new BrotliStream(s, CompressionMode.Decompress), out complete),
                "deflate" => InflateDeflate(data, out complete),
                _ => null
            };

            if (decoded is null)
            {
                note = $"corps compressé en « {encoding} » : format non pris en charge, affiché tel quel";
                return data;
            }

            note = complete
                ? $"décompressé ({contentEncoding}) : {wireBody.Length} → {decoded.Length} octets"
                : $"décompression incomplète ({contentEncoding}) : données tronquées dans la capture";
            data = decoded;
        }

        return data;
    }

    /// <summary>"deflate" HTTP est en pratique du zlib ; certains serveurs envoient du deflate brut.</summary>
    private static byte[]? InflateDeflate(byte[] data, out bool complete)
    {
        var zlib = Inflate(data, s => new ZLibStream(s, CompressionMode.Decompress), out complete);
        if (zlib is { Length: > 0 })
            return zlib;

        return Inflate(data, s => new DeflateStream(s, CompressionMode.Decompress), out complete);
    }

    private static byte[] Inflate(byte[] data, Func<Stream, Stream> createDecoder, out bool complete)
    {
        complete = true;
        using var input = new MemoryStream(data);
        using var decoder = createDecoder(input);
        using var output = new MemoryStream();

        var buffer = new byte[8192];
        try
        {
            int read;
            while ((read = decoder.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
                if (output.Length > MaxDecodedBytes)
                {
                    complete = false;
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or EndOfStreamException)
        {
            complete = false;   // flux tronque ou corrompu : on garde ce qui a pu etre lu
        }

        return output.ToArray();
    }
}