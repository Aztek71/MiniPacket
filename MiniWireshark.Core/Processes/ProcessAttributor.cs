using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using MiniWireshark.Models;

namespace MiniWireshark.Core.Processes;

/// <summary>
/// Attribue chaque paquet TCP/UDP au processus (.exe) qui possede le socket, en relisant regulierement la table des
/// connexions du systeme (comme TCPView). La capture se fait au niveau de la carte reseau, qui ne connait pas les
/// processus : l'association se fait par correspondance des adresses et des ports.
///
/// Limite inherente : une connexion ouverte et fermee entre deux relevés (250 ms) n'apparait jamais dans la table.
/// Les paquets non attribues immediatement (le SYN part avant le premier releve) sont gardes 10 secondes et rattrapes
/// des que leur connexion apparait : l'evenement ProcessesResolved le signale (sur le thread du timer).
/// </summary>
public sealed class ProcessAttributor : IDisposable
{
    private const int RefreshIntervalMs = 250;
    private const int MaxPendingPackets = 5000;

    private static readonly TimeSpan PendingWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan LocalAddressRefresh = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan NameRefresh = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan NameRetention = TimeSpan.FromMinutes(2);

    // Processus systeme dont le nom n'a pas d'extension .exe
    private static readonly HashSet<string> NamesWithoutExtension = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Idle", "Memory Compression", "Secure System", "vmmem"
    };

    private readonly Func<IReadOnlyList<ProcessConnection>> _readConnections;
    private readonly Func<int, string?> _resolveName;
    private readonly Func<IEnumerable<string>> _readLocalAddresses;
    private readonly Func<DateTime> _clock;

    private readonly object _lock = new();
    private readonly object _refreshLock = new();
    private readonly ProcessConnectionMap _map = new();
    private readonly Dictionary<int, (string? Name, DateTime Resolved)> _names = new();
    private readonly List<(CapturedPacket Packet, DateTime Since)> _pending = new();
    private HashSet<string> _localAddresses = new();
    private DateTime _localAddressesRead = DateTime.MinValue;
    private HashSet<int> _currentPids = new();
    private Timer? _timer;

    /// <summary>Faux hors Windows : l'attribution est alors un no-op.</summary>
    public bool IsSupported { get; }

    /// <summary>
    /// Declenche (sur un thread du timer) quand des paquets deja publies viennent d'etre rattaches a un processus.
    /// Le recepteur doit appeler CapturedPacket.SetProcess depuis le thread de l'interface.
    /// </summary>
    public event Action<IReadOnlyList<(CapturedPacket Packet, int Pid, string Name)>>? ProcessesResolved;

    public ProcessAttributor()
        : this(ReadSystemConnections, ResolveProcessName, ReadLocalAddresses, OperatingSystem.IsWindows())
    {
    }

    /// <summary>Constructeur avec sources injectables (tests) : releve des connexions, noms de processus, adresses locales, horloge.</summary>
    public ProcessAttributor(
        Func<IReadOnlyList<ProcessConnection>> readConnections,
        Func<int, string?> resolveName,
        Func<IEnumerable<string>> readLocalAddresses,
        bool isSupported = true,
        Func<DateTime>? clock = null)
    {
        _readConnections = readConnections;
        _resolveName = resolveName;
        _readLocalAddresses = readLocalAddresses;
        _clock = clock ?? (() => DateTime.UtcNow);
        IsSupported = isSupported;
    }

    public void Start()
    {
        if (!IsSupported)
            return;

        SafeRefresh();
        _timer ??= new Timer(_ => SafeRefresh(), null, RefreshIntervalMs, RefreshIntervalMs);
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    /// <summary>Oublie les paquets en attente (nouvelle capture). La table des connexions, elle, est conservee.</summary>
    public void Reset()
    {
        lock (_lock)
            _pending.Clear();
    }

    public void Dispose() => Stop();

    /// <summary>Noms des applications ayant des connexions au dernier releve, sans doublon, tries.</summary>
    public IReadOnlyList<string> GetApplicationNames()
    {
        lock (_lock)
        {
            return _currentPids
                .Select(pid => _names.TryGetValue(pid, out var entry) ? entry.Name : null)
                .Where(name => !string.IsNullOrEmpty(name))
                .Select(name => name!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    /// <summary>
    /// A appeler pour chaque paquet, sur le thread de capture, avant sa publication. Si le processus est deja connu,
    /// il est inscrit sur le paquet ; sinon le paquet est garde pour un rattrapage au prochain releve.
    /// </summary>
    public void Attribute(CapturedPacket packet)
    {
        if (!IsSupported || (packet.Tcp is null && packet.Udp is null))
            return;

        lock (_lock)
        {
            if (TryLookup(packet, out int pid, out string name))
            {
                packet.SetProcess(pid, name);
                return;
            }

            _pending.Add((packet, _clock()));
            if (_pending.Count > MaxPendingPackets)
                _pending.RemoveRange(0, _pending.Count - MaxPendingPackets);
        }
    }

    /// <summary>Relit la table des connexions et rattrape les paquets en attente. Sans effet si un releve est deja en cours.</summary>
    public void RefreshNow()
    {
        if (!Monitor.TryEnter(_refreshLock))
            return;

        var resolved = new List<(CapturedPacket, int, string)>();
        try
        {
            IReadOnlyList<ProcessConnection> rows;
            try
            {
                rows = _readConnections();
            }
            catch (Exception)
            {
                return;   // API indisponible ou refusee : on garde l'etat precedent
            }

            DateTime now = _clock();
            var pids = rows.Select(r => r.Pid).Distinct().ToList();

            // Les appels lents (noms de processus, interfaces reseau) se font hors du verrou : la capture ne doit pas attendre.
            List<int> toResolve;
            lock (_lock)
                toResolve = pids.Where(pid => !_names.TryGetValue(pid, out var e) || now - e.Resolved > NameRefresh).ToList();

            var newNames = toResolve.ToDictionary(pid => pid, pid => _resolveName(pid));

            HashSet<string>? newLocalAddresses = null;
            if (now - _localAddressesRead > LocalAddressRefresh)
                newLocalAddresses = new HashSet<string>(SafeLocalAddresses());

            lock (_lock)
            {
                foreach (var (pid, name) in newNames)
                    _names[pid] = (name, now);

                var current = new HashSet<int>(pids);
                foreach (var stale in _names.Where(kv => !current.Contains(kv.Key) && now - kv.Value.Resolved > NameRetention).Select(kv => kv.Key).ToList())
                    _names.Remove(stale);

                if (newLocalAddresses is not null)
                {
                    _localAddresses = newLocalAddresses;
                    _localAddressesRead = now;
                }

                _currentPids = current;
                _map.Update(rows, now);

                for (int i = _pending.Count - 1; i >= 0; i--)
                {
                    var (packet, since) = _pending[i];
                    if (now - since > PendingWindow)
                    {
                        _pending.RemoveAt(i);
                    }
                    else if (TryLookup(packet, out int pid, out string name))
                    {
                        _pending.RemoveAt(i);
                        resolved.Add((packet, pid, name));
                    }
                }
            }
        }
        finally
        {
            Monitor.Exit(_refreshLock);
        }

        if (resolved.Count > 0)
            ProcessesResolved?.Invoke(resolved);
    }

    private void SafeRefresh()
    {
        // Une exception sur le thread du timer ferait tomber tout le processus : on avale tout.
        try
        {
            RefreshNow();
        }
        catch (Exception)
        {
        }
    }

    private IEnumerable<string> SafeLocalAddresses()
    {
        try
        {
            return _readLocalAddresses().ToList();
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>Doit etre appelee sous _lock.</summary>
    private bool TryLookup(CapturedPacket packet, out int pid, out string name)
    {
        pid = 0;
        name = string.Empty;

        IPAddress? src = packet.IPv4?.SourceAddress ?? packet.IPv6?.SourceAddress;
        IPAddress? dst = packet.IPv4?.DestinationAddress ?? packet.IPv6?.DestinationAddress;
        if (src is null || dst is null)
            return false;

        bool isTcp;
        ushort srcPort, dstPort;
        if (packet.Tcp is { } tcp)
        {
            isTcp = true;
            srcPort = tcp.SourcePort;
            dstPort = tcp.DestinationPort;
        }
        else if (packet.Udp is { } udp)
        {
            isTcp = false;
            srcPort = udp.SourcePort;
            dstPort = udp.DestinationPort;
        }
        else
        {
            return false;
        }

        int? found = _map.Find(isTcp, src, srcPort, dst, dstPort, address => _localAddresses.Contains(AddressText.Normalize(address)));
        if (found is null)
            return false;

        pid = found.Value;
        name = _names.TryGetValue(pid, out var entry) && !string.IsNullOrEmpty(entry.Name) ? entry.Name! : $"PID {pid}";
        return true;
    }

    // ----- Sources reelles (Windows) -----

    private static IReadOnlyList<ProcessConnection> ReadSystemConnections() =>
        OperatingSystem.IsWindows() ? NativeConnectionTable.Read() : Array.Empty<ProcessConnection>();

    private static string? ResolveProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string name = process.ProcessName;   // sans extension sous Windows
            return NamesWithoutExtension.Contains(name) ? name : name + ".exe";
        }
        catch (Exception)
        {
            return null;   // processus termine entre-temps, ou acces refuse
        }
    }

    private static IEnumerable<string> ReadLocalAddresses()
    {
        var addresses = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                addresses.Add(AddressText.Normalize(unicast.Address));
        return addresses;
    }
}