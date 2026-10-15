namespace MiniWireshark.Core.Http;

public sealed class HttpMessage
{
    public int? StreamId { get; set; }
    public bool FromClient { get; set; }
    public string StartLine { get; set; } = string.Empty;
    public List<(string Name, string Value)> Headers { get; } = new();
    public List<(string Name, string Value)> Trailers { get; } = new();
    public int WireBodyLength { get; set; }
    public byte[] Body { get; set; } = Array.Empty<byte>();
    public string? BodyNote { get; set; }
    public bool EndedStream { get; set; }

    public string? Header(string name)
    {
        foreach (var (headerName, value) in Headers)
            if (string.Equals(headerName, name, StringComparison.OrdinalIgnoreCase))
                return value;
        return null;
    }

}