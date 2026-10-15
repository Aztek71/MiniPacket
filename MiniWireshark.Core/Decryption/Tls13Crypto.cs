using System.Security.Cryptography;
using System.Text;

namespace MiniWireshark.Core.Decryption;

internal sealed record Tls13Suite(ushort Id, string Name, HashAlgorithmName Hash, int KeyLength, bool IsChaCha);

internal static class Tls13CipherSuites
{
    private static readonly Tls13Suite[] Supported =
    {
        new(0x1301, "TLS_AES_128_GCM_SHA256", HashAlgorithmName.SHA256, 16, false),
        new(0x1302, "TLS_AES_256_GCM_SHA384", HashAlgorithmName.SHA384, 32, false),
        new(0x1303, "TLS_CHACHA20_POLY1305_SHA256", HashAlgorithmName.SHA256, 32, true)
    };

    public static bool TryGet(ushort id, out Tls13Suite suite)
    {
        foreach (var candidate in Supported)
        {
            if (candidate.Id == id)
            {
                suite = candidate;
                return true;
            }
        }

        suite = null!;
        return false;
    }

    public static string NameOf(ushort id) => id switch
    {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        _ => $"Unknown (0x{id:X4})"
    };
}

internal sealed class Tls13RecordKeys
{
    private const int TagLength = 16; // GCM tag length is always 16 bytes
    private readonly Tls13Suite _suite;
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private ulong _sequence;

    public Tls13RecordKeys(Tls13Suite suite, byte[] trafficSecret)
    {
        _suite = suite;
        _key = HkdfExpandLabel(suite.Hash, trafficSecret, "key", Array.Empty<byte>(), suite.KeyLength);
        _iv = HkdfExpandLabel(suite.Hash, trafficSecret, "iv", Array.Empty<byte>(), 12);
    }

    internal static byte[] HkdfExpandLabel(HashAlgorithmName hash, byte[] secret, string label, byte[] context, int length)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);

        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)labelBytes.Length;
        Buffer.BlockCopy(labelBytes, 0, info, 3, labelBytes.Length);
        info[3 + labelBytes.Length] = (byte)context.Length;
        Buffer.BlockCopy(context, 0, info, 4 + labelBytes.Length, context.Length);

        return HKDF.Expand(hash, secret, length, info);
    }

    public bool TryDecrypt(ReadOnlySpan<byte> header, ReadOnlySpan<byte> protectedPayload, out byte innerType, out byte[] content)
    {
        innerType = 0;
        content = Array.Empty<byte>();

        if (protectedPayload.Length < TagLength + 1)
            return false;

        int ciphertextLength = protectedPayload.Length - TagLength;
        var ciphertext = protectedPayload[..ciphertextLength];
        var tag = protectedPayload[ciphertextLength..];

        Span<byte> nonce = stackalloc byte[12];
        _iv.CopyTo(nonce);
        for (int i = 0; i < 8; i++)
            nonce[11 - i] ^= (byte)(_sequence >> (8 * i));

        var plaintext = new byte[ciphertext.Length];
        try
        {
            if (_suite.IsChaCha)
            {
                using var chacha = new ChaCha20Poly1305(_key);
                chacha.Decrypt(nonce, ciphertext, tag, plaintext, header);
            }
            else
            {
                using var aes = new AesGcm(_key, TagLength);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, header);
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        int last = plaintext.Length - 1;
        while (last >= 0 && plaintext[last] == 0)
            last--;

        if (last < 0)
            return false;
        
        innerType = plaintext[last];
        content = plaintext.AsSpan(0, last).ToArray();
        _sequence++;
        return true;
    }
}