namespace MiniWireshark.Core.Http;

public class HttpConversation
{
    public IReadOnlyList<HttpMessage> Messages { get; init; } = Array.Empty<HttpMessage>();

    public IReadOnlyList<string> ConnectionEvents { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Problems { get; init; } = Array.Empty<string>();
}