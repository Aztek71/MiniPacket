using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace MiniWireshark.Core.Processes;

[SupportedOSPlatform("windows")]
internal static class NativeConnectionTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

    public static List<ProcessConnection> Read()
    {
        var all = new List<ProcessConnection>();
        all.AddRange(ConnectionTableParser.ParseTcp(Fetch(tcp: true, AfInet), ipv6: false));
        all.AddRange(ConnectionTableParser.ParseTcp(Fetch(tcp: true, AfInet6), ipv6: true));
        all.AddRange(ConnectionTableParser.ParseUdp(Fetch(tcp: false, AfInet), ipv6: false));
        all.AddRange(ConnectionTableParser.ParseUdp(Fetch(tcp: false, AfInet6), ipv6: true));
        return all;
    }

    private static byte[] Fetch(bool tcp, int addressFamily)
    {
        int size = 0;

        for (int attempt = 0; attempt < 5; attempt++)
        {
            IntPtr buffer = IntPtr.Zero();
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