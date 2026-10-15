using System.Text;

namespace MiniWireshark.Core.Decryption;

public sealed class KeyLog
{
    private readonly Dictionary<string, Dictionary<string, byte[]>> _secretsByClientRandom = new(StringComparer.OrdinalIgnoreCase);
    public int EntryCount { get; private set;}

    public static KeyLog Load(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.ASCII);
        return Parse(reader.ReadToEnd());
    }

    public static KeyLog Parse(string text)
    {
        var log = new KeyLog();
        foreach (var rawLine in text.Split('\n'))
            log.AddLine(rawLine);
        return log;
    }

    private void AddLine(string rawLine)
    {
        string line = rawLine.Trim();
        if (line.Length == 0 || line[0] == '#')
            return;
        
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
            return;
        
        byte[] secret;
        try
        {
            Convert.FromHexString(parts[1]);
            secret = Convert.FromHexString(parts[2]);
        }
        catch (FormatException)
        {
            return;
        }

        if (!_secretsByClientRandom.TryGetValue(parts[1], out var byLabel))
        {
            byLabel = new Dictionary<string, byte[]>();
            _secretsByClientRandom[parts[1]] = byLabel;
        }

        byLabel[parts[0]] = secret;
        EntryCount++;
    }

    public byte[]? Find(byte[] clientRandom, string label)
    {
        string key = Convert.ToHexString(clientRandom);
        return _secretsByClientRandom.TryGetValue(key, out var byLabel) && byLabel.TryGetValue(label, out var secret)
            ? secret
            : null;
    }
}