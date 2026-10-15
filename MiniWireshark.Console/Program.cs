using MiniWireshark.Core;
using MiniWireshark.Models;

Console.WriteLine("=== Mini Wireshark (C#) ===\n");

var devices = PacketCaptureService.ListDevices();
if (devices.Count == 0)
{
    Console.WriteLine("Aucune interface réseau trouvée. As-tu installé Npcap (Windows) ou libpcap (Linux/Mac) ?");
    return;
}

Console.WriteLine("Interfaces disponibles :");
for (int i = 0; i < devices.Count; i++)
    Console.WriteLine($"  [{i}] {devices[i].Description ?? devices[i].Name}");

Console.Write("\nChoisis une interface (numéro) : ");
if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 0 || choice >= devices.Count)
{
    Console.WriteLine("Choix invalide.");
    return;
}

Console.Write("Filtre BPF optionnel (ex: 'tcp port 443', ou vide pour tout capturer) : ");
string? filter = Console.ReadLine();

using var capture = new PacketCaptureService();

capture.OnPacketCaptured += PrintPacket;

Console.WriteLine("\nCapture en cours... Ctrl+C pour arrêter.\n");
PrintHeader();

capture.Start(devices[choice], string.IsNullOrWhiteSpace(filter) ? null : filter);

// Garde le programme actif jusqu'à Ctrl+C
var exitEvent = new ManualResetEvent(false);
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    exitEvent.Set();
};
exitEvent.WaitOne();

capture.Stop();
Console.WriteLine("\nCapture arrêtée.");

static void PrintHeader()
{
    Console.WriteLine($"{"No.",-6}{"Heure",-14}{"Source",-18}{"Destination",-18}{"Proto",-8}{"Len",-6}Info");
    Console.WriteLine(new string('-', 110));
}

static void PrintPacket(CapturedPacket packet)
{
    Console.WriteLine(
        $"{packet.Number,-6}" +
        $"{packet.Timestamp:HH:mm:ss.fff,-14}" +
        $"{packet.Source,-18}" +
        $"{packet.Destination,-18}" +
        $"{packet.TopProtocol,-8}" +
        $"{packet.Length,-6}" +
        $"{packet.Info}");
}
