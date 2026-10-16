using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace MiniWireshark.Gui.Converters;

/// <summary>
/// Associe un protocole (TopProtocol d'un CapturedPacket) à une couleur de fond de ligne,
/// façon coloring rules de Wireshark. Couleurs semi-transparentes pour rester lisibles
/// aussi bien en thème clair qu'en thème sombre.
/// </summary>
public sealed class ProtocolToBrushConverter : IValueConverter
{
    // Alpha volontairement bas (teinte, pas un aplat) pour ne jamais écraser le texte.
    private static readonly IBrush Tcp = new SolidColorBrush(Color.FromArgb(0x28, 0x64, 0x95, 0xED));      // bleu (cornflower)
    private static readonly IBrush Udp = new SolidColorBrush(Color.FromArgb(0x28, 0x90, 0xEE, 0x90));      // vert clair
    private static readonly IBrush Arp = new SolidColorBrush(Color.FromArgb(0x28, 0xFF, 0xA5, 0x00));      // orange
    private static readonly IBrush Icmp = new SolidColorBrush(Color.FromArgb(0x28, 0xFF, 0xD7, 0x00));     // or
    private static readonly IBrush Ipv6 = new SolidColorBrush(Color.FromArgb(0x28, 0xDD, 0xA0, 0xDD));     // prune
    private static readonly IBrush Vlan = new SolidColorBrush(Color.FromArgb(0x28, 0xA9, 0xA9, 0xA9));     // gris
    private static readonly IBrush Dns = new SolidColorBrush(Color.FromArgb(0x28, 0x40, 0xE0, 0xD0));      // turquoise
    private static readonly IBrush Tls = new SolidColorBrush(Color.FromArgb(0x28, 0x93, 0x70, 0xDB));      // violet
    private static readonly IBrush Default = Brushes.Transparent;
    private static readonly IBrush AnomalyWarning = new SolidColorBrush(Color.FromArgb(0x55, 0xFF, 0x8C, 0x00));   // orange vif
    private static readonly IBrush AnomalyError = new SolidColorBrush(Color.FromArgb(0x60, 0xFF, 0x30, 0x30));     // rouge

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var protocol = value as string;

        return protocol switch
        {
            "TCP" => Tcp,
            "UDP" => Udp,
            "ARP" => Arp,
            "ICMP" => Icmp,
            "IPv6" => Ipv6,
            "VLAN (802.1Q)" => Vlan,
            "TLS" => Tls,
            "DNS" => Dns,
            "ANOMALY_WARNING" => AnomalyWarning,
            "ANOMALY_ERROR" => AnomalyError,
            _ => Default
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}