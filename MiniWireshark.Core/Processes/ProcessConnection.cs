using System.Net;

namespace MiniWireshark.Core.Processes;

public sealed record ProcessConnection(
    bool isTcp,
    IPAddress LocalAddress,
    ushort LocalPort,
    IPAddress? RemoteAddress,
    ushort RemotePort,
    int Pid,
    bool isListening);

internal static class AddressText
{
    public static string Normalize(IPAddress address) => new IPAddress(address.GetAddressBytes()).ToString();

    public static bool IsWildcard(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
}