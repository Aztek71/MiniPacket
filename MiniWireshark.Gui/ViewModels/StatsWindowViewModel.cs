using System;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using MiniWireshark.Core;
using MiniWireshark.Core.Localization;

namespace MiniWireshark.Gui.ViewModels;

/// <summary>
/// Pilote la fenetre de statistiques : interroge CaptureStatistics toutes les 500ms via un DispatcherTimer
/// et republie des collections pretes a l'affichage (barres normalisees, lignes formatees).
/// </summary>
public partial class StatsWindowViewModel : ObservableObject, IDisposable
{
    private const int PpsWindowSeconds = 60;
    private const double MaxBarHeight = 100;

    private readonly PacketCaptureService _captureService;
    private readonly DispatcherTimer _timer;

    public ObservableCollection<double> PacketsPerSecondBars { get; } = new();
    public ObservableCollection<ProtocolStatRow> ProtocolBreakdown { get; } = new();
    public ObservableCollection<TalkerRow> TopTalkers { get; } = new();

    [ObservableProperty]
    private int _totalPackets;

    [ObservableProperty]
    private string _totalBytesDisplay = string.Empty;

    [ObservableProperty]
    private int _activeTcpStreams;

    [ObservableProperty]
    private int _currentPacketsPerSecond;

    public StatsWindowViewModel(PacketCaptureService captureService)
    {
        _captureService = captureService;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();

        Refresh();
    }

    private void Refresh()
    {
        var stats = _captureService.Statistics;

        TotalPackets = stats.TotalPackets;
        TotalBytesDisplay = FormatBytes(stats.TotalBytes);
        ActiveTcpStreams = _captureService.StreamTracker.Streams.Count;

        var pps = stats.GetPacketsPerSecond(PpsWindowSeconds);
        CurrentPacketsPerSecond = pps.Count > 0 ? pps[^1] : 0;

        int max = Math.Max(1, pps.Count > 0 ? pps.Max() : 0);
        PacketsPerSecondBars.Clear();
        foreach (var count in pps)
            PacketsPerSecondBars.Add(count == 0 ? 0 : Math.Max(2, count / (double)max * MaxBarHeight));

        var breakdown = stats.GetProtocolBreakdown();
        int total = Math.Max(1, stats.TotalPackets);
        ProtocolBreakdown.Clear();
        foreach (var (protocol, count) in breakdown)
            ProtocolBreakdown.Add(new ProtocolStatRow(protocol, count, count * 100.0 / total));

        TopTalkers.Clear();
        foreach (var talker in stats.GetTopTalkers(10))
            TopTalkers.Add(new TalkerRow(talker.Address, talker.PacketCount, FormatBytes(talker.ByteCount)));
    }

    /// <summary>Volume lisible, dans la langue choisie (o/Ko/Mo/Go ou B/KB/MB/GB, virgule ou point decimal).</summary>
    private static string FormatBytes(long bytes)
    {
        string[] units = { Localizer.T("unit_b"), Localizer.T("unit_kb"), Localizer.T("unit_mb"), Localizer.T("unit_gb") };
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value.ToString("0.#", Localizer.Instance.Culture)} {units[unit]}";
    }

    /// <summary>Arrete le timer de rafraichissement — a appeler quand la fenetre se ferme, sinon elle tourne indefiniment.</summary>
    public void Dispose() => _timer.Stop();
}