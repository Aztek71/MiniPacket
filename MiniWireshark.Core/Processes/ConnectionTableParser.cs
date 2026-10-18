using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;

namespace MiniWireshark.Core.Processes;

internal static class ConnectionTableParser
{
    private const int TcpStateListen = 2;
    private const int HeaderSize = 4;

    private const int Tcp4RowSize = 24;
    private const int Tcp6RowSize = 56;
    private const int Udp4RowSize = 12;
    private const int Udp6RowSize = 28;

    public static List<ProcessConnection> ParseTcp(ReadOnlySpan<byte> table, bool ipv6)
    {
        var result = new List<ProcessConnection>();
        if (table.Length < HeaderSize)
            return result;
        
        int count = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(table), int.MaxValue);
        int rowSize = ipv6 ? Tcp6RowSize : Tcp4RowSize;

        for (int i = 0; i < count; i++)
        {
            int o = HeaderSize + i * rowSize;
            if (o + rowSize > table.Length)
                break;
            
            int pid;
            int state;
            IPAddress local, remote;
            ushort localPort, remotePort;

            if (ipv6)
            {
                local = new IPAddress(table.Slice(o, 16));
                localPort = ReadPort(table, o + 20);
                remote = new IPAddress(table.Slice(o + 24, 16));
                remotePort = ReadPort(table, o + 44);
                state = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o + 48));
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o + 52));
            }
            else
            {
                state = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o));
                local = new IPAddress(table.Slice(o + 4, 4));
                localPort = ReadPort(table, o + 8);
                remote = new IPAddress(table.Slice(o + 12, 4));
                remotePort = ReadPort(table, o + 16);
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o + 20));
            }

            if (pid == 0)
                continue;
            
            bool listening = state == TcpStateListen;
            result.Add(new ProcessConnection(true, local, localPort, listening ? null : remote, listening ? (ushort)0 : remotePort, pid, listening));
        }

        return result;
    }

    public static List<ProcessConnection> ParseUdp(ReadOnlySpan<byte> table, bool ipv6)
    {
        var result = new List<ProcessConnection>();
        if (table.Length < HeaderSize)
            return result;

        int count = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(table), int.MaxValue);
        int rowSize = ipv6 ? Udp6RowSize : Udp4RowSize;

        for (int i = 0; i < count; i++)
        {
            int o = HeaderSize + i * rowSize;
            if (o + rowSize > table.Length)
                break;

            IPAddress local;
            ushort localPort;
            int pid;

            if (ipv6)
            {
                local = new IPAddress(table.Slice(o, 16));
                localPort = ReadPort(table, o + 20);
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o + 24));
            }
            else
            {
                local = new IPAddress(table.Slice(o, 4));
                localPort = ReadPort(table, o + 4);
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(table.Slice(o + 8));
            }

            if (pid == 0)
                continue;

            result.Add(new ProcessConnection(false, local, localPort, null, 0, pid, false));
        }

        return result;
    }

    private static ushort ReadPort(ReadOnlySpan<byte> data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);
}