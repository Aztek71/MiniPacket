using System.Text;

namespace MiniWireshark.Core.Http;

internal static class HttpText
{
    public static string FixEncoding(string latin1)
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