using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace MiniWireshark.Core.Processes;

/// <summary>
/// Lecture de la table des connexions de Windows via l'API IP Helper (iphlpapi.dll). C'est la meme source que
/// TCPView ou "netstat -ano". Fine enveloppe : tout le decodage est dans ConnectionTableParser.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class NativeConnectionTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;   // TCP_TABLE_OWNER_PID_ALL : toutes les connexions, avec le PID
    private const int UdpTableOwnerPid = 1;      // UDP_TABLE_OWNER_PID
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

    public static List<ProcessConnection> Read()
    {
        var all = new List<ProcessConnection>();
        all.AddRange(ConnectionTableParser.ParseTcp(Fetch(tcp: true, AfInet), ipv6: false));
        all.AddRange(ConnectionTableParser.ParseTcp(Fetch(tcp: true, AfInet6), ipv6: true));
        all.AddRange(ConnectionTableParser.ParseUdp(Fetch(tcp: false, AfInet), ipv6: false));
        all.AddRange(ConnectionTableParser.ParseUdp(Fetch(tcp: false, AfInet6), ipv6: true));
        return all;
    }

    /// <summary>
    /// Le premier appel (tampon vide) renvoie la taille necessaire ; la table pouvant grossir entre deux appels,
    /// on garde une marge et on recommence quelques fois si besoin.
    /// </summary>
    private static byte[] Fetch(bool tcp, int addressFamily)
    {
        int size = 0;

        for (int attempt = 0; attempt < 5; attempt++)
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                if (size > 0)
                    buffer = Marshal.AllocHGlobal(size);

                uint result = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, addressFamily, TcpTableOwnerPidAll, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, addressFamily, UdpTableOwnerPid, 0);

                if (result == NoError)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buffer, bytes, 0, size);
                    return bytes;
                }

                if (result != ErrorInsufficientBuffer)
                    return Array.Empty<byte>();

                size += 4096;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }

        return Array.Empty<byte>();
    }
}