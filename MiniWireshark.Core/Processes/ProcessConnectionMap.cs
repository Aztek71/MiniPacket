using System.Net;
using System.Security.Cryptography;

namespace MiniWireshark.Core.Processes;

internal sealed class ProcessConnectionMap
{
    private sealed class Entry
    {
        public int Pid;
        public DateTime LastSeen;
    }

    private static readonly TimeSpan Retention = TimeSpan.FromSeconds(15);

    private readonly Dictionary<string, Entry> _tcpConnections = new();
    private readonly Dictionary<string, Entry> _tcpListeners = new();
    private readonly Dictionary<string, Entry> _udpSockets = new();

    public void Update(IEnumerable<ProcessConnection> connections, DateTime now)
    {
        foreach (var c in connections)
        {
            if (c.IsTcp && c.Listening)
                Put(_tcpListeners, EndpointKey(c.LocalAddress, c.LocalPort), c.Pid, now);
            else if (c.IsTcp && c.RemoteAddress is not null)
                Put(_tcpConnections, ConnectionKey(c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort), c.Pid, now);
            else if (!c.IsTcp)
                Put(_udpSockets, EndpointKey(c.LocalAddress, c.LocalPort), c.Pid, now);
        }

        Expire(_tcpConnections, now);
        Expire(_tcpListeners, now);
        Expire(_udpSockets, now);
    }

    public int? Find(bool isTcp, IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort, Func<IPAddress, bool> isLocal)
    {
        if (isTcp)
        {
            if (_tcpConnections.TryGetValue(ConnectionKey(srcIp, srcPort, dstIp, dstPort), out var outgoing))
                return outgoing.Pid;
            if (_tcpConnections.TryGetValue(ConnectionKey(dstIp, dstPort, srcIp, srcPort), out var incoming))
                return incoming.Pid;

            return FindEndpoint(_tcpListeners, dstIp, dstPort) ?? FindEndpoint(_tcpListeners, srcIp, srcPort);
        }
        int? fromSource = isLocal(srcIp) ? FindEndpoint(_udpSockets, srcIp, srcPort) : null;
        return fromSource ?? (isLocal(dstIp) ? FindEndpoint(_udpSockets, dstIp, dstPort) : null);
    }

    private static int? FindEndpoint(Dictionary<string, Entry> sockets, IPAddress address, ushort port)
    {
        if (sockets.TryGetValue(EndpointKey(address, port), out var exact))
            return exact.Pid;
        
        if (sockets.TryGetValue(WildcardKey(port), out var wildcard))
            return wildcard.Pid;
        
        return null;
    }

    private static void Put(Dictionary<string, Entry> table, string key, int pid, DateTime now)
    {
        if (table.TryGetValue(key, out var entry))
        {
            entry.Pid = pid;
            entry.LastSeen = now;
        }
        else
        {
            table[key] = new Entry { Pid = pid, LastSeen = now };
        }
    }

    private static void Expire(Dictionary<string, Entry> table, DateTime now)
    {
        foreach (var key in table.Where(kv => now - kv.Value.LastSeen > Retention).Select(kv => kv.Key).ToList())
            table.Remove(key);
    }

    private static string WildcardKey(ushort port) => $"*|{port}";

    private static string EndpointKey(IPAddress address, ushort port) =>
        AddressText.IsWildcard(address) ? WildcardKey(port) : $"{AddressText.Normalize(address)}|{port}";

    private static string ConnectionKey(IPAddress local, ushort localPort, IPAddress remote, ushort remotePort) =>
        $"{AddressText.Normalize(local)}|{localPort}|{AddressText.Normalize(remote)}|{remotePort}";
}