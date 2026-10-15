using MiniWireshark.Models;

namespace MiniWireshark.Core.Filtering;

/// <summary>Un filtre compilé, prêt à être testé contre des paquets.</summary>
public interface IPacketFilter
{
    bool Matches(CapturedPacket packet);
}

internal sealed class AcceptAllFilter : IPacketFilter
{
    public static readonly AcceptAllFilter Instance = new();
    public bool Matches(CapturedPacket packet) => true;
}

internal sealed class CompiledFilter(FilterNode root) : IPacketFilter
{
    public bool Matches(CapturedPacket packet) => root.Evaluate(packet);
}

/// <summary>
/// Compile une expression de filtre display façon Wireshark en un <see cref="IPacketFilter"/> réutilisable.
/// Exemples : "tcp.port == 443", "ip.addr == 192.168.1.8 and tcp.flags.syn == 1", "udp or arp", "not tcp".
/// </summary>
public static class DisplayFilter
{
    /// <summary>Filtre neutre qui accepte tous les paquets — utilisé quand l'expression est vide.</summary>
    public static readonly IPacketFilter AcceptAll = AcceptAllFilter.Instance;

    /// <summary>
    /// Parse et compile une expression de filtre. Lève <see cref="DisplayFilterException"/> avec un message
    /// destiné à être affiché tel quel à l'utilisateur si l'expression est invalide.
    /// </summary>
    public static IPacketFilter Parse(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return AcceptAll;

        var tokens = Tokenizer.Tokenize(expression);
        var parser = new Parser(tokens);
        var root = parser.ParseExpression();
        parser.ExpectEof();
        return new CompiledFilter(root);
    }
}