using System;
using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MiniWireshark.Core;
using MiniWireshark.Core.Filtering;
using MiniWireshark.Core.Streams;
using MiniWireshark.Gui.Views;
using MiniWireshark.Models;
using SharpPcap;

namespace MiniWireshark.Gui.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    private readonly PacketCaptureService _captureService = new();

    /// <summary>Le filtre display actuellement actif — DisplayFilter.AcceptAll si aucun filtre n'est appliqué.</summary>
    private IPacketFilter _activeFilter = DisplayFilter.AcceptAll;

    /// <summary>Interfaces réseau disponibles, remplies une fois au démarrage.</summary>
    public ObservableCollection<ICaptureDevice> Interfaces { get; } = new();

    /// <summary>Tous les paquets capturés, sans filtrage — sert de source pour le recalcul du filtre.</summary>
    public ObservableCollection<CapturedPacket> Packets { get; } = new();

    /// <summary>Les paquets après application du filtre display — c'est ce que le DataGrid affiche.</summary>
    public ObservableCollection<CapturedPacket> FilteredPackets { get; } = new();

    /// <summary>Détail du paquet sélectionné — équivalent du panneau "Packet Details".</summary>
    public ObservableCollection<PacketDetailNode> DetailNodes { get; } = new();

    [ObservableProperty]
    private ICaptureDevice? _selectedInterface;

    /// <summary>Filtre BPF appliqué au niveau de la capture (ex: "tcp port 443") — immuable une fois la capture démarrée.</summary>
    [ObservableProperty]
    private string _captureFilterText = string.Empty;

    /// <summary>Filtre display appliqué après coup sur les paquets déjà capturés (ex: "tcp.port == 443").</summary>
    [ObservableProperty]
    private string _displayFilterText = string.Empty;

    /// <summary>Message d'erreur de parsing du filtre display, affiché sous le champ — null si l'expression est valide.</summary>
    [ObservableProperty]
    private string? _filterErrorMessage;

    [ObservableProperty]
    private bool _isCapturing;

    [ObservableProperty]
    private string _statusMessage = "Sélectionne une interface puis clique sur Démarrer.";

    [ObservableProperty]
    private CapturedPacket? _selectedPacket;

    public MainWindowViewModel()
    {
        foreach (var device in PacketCaptureService.ListDevices())
            Interfaces.Add(device);

        _captureService.OnPacketCaptured += packet =>
        {
            // La capture arrive sur le thread de SharpPcap : on repasse sur le thread UI Avalonia
            // avant de toucher aux ObservableCollection, sous peine d'exception cross-thread.
            Dispatcher.UIThread.Post(() =>
            {
                Packets.Add(packet);
                if (_activeFilter.Matches(packet))
                    FilteredPackets.Add(packet);

                UpdateStatusMessage();
            });
        };
    }

    partial void OnSelectedPacketChanged(CapturedPacket? value)
    {
        DetailNodes.Clear();
        if (value is null)
        {
            FollowTcpStreamCommand.NotifyCanExecuteChanged();
            return;
        }

        foreach (var node in PacketDetailBuilder.Build(value))
            DetailNodes.Add(node);

        FollowTcpStreamCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void Start()
    {
        if (SelectedInterface is null)
            return;

        try
        {
            Packets.Clear();
            FilteredPackets.Clear();
            DetailNodes.Clear();
            _captureService.Start(SelectedInterface, string.IsNullOrWhiteSpace(CaptureFilterText) ? null : CaptureFilterText);
            IsCapturing = true;
            StatusMessage = $"Capture en cours sur {SelectedInterface.Description ?? SelectedInterface.Name}...";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erreur au démarrage : {ex.Message}";
        }
    }

    private bool CanStart() => !IsCapturing && SelectedInterface is not null;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void Stop()
    {
        _captureService.Stop();
        IsCapturing = false;
        UpdateStatusMessage();
    }

    private bool CanStop() => IsCapturing;

    /// <summary>Parse et applique le filtre display saisi. En cas d'erreur de syntaxe, le filtre actif précédent est conservé.</summary>
    [RelayCommand]
    private void ApplyFilter()
    {
        try
        {
            _activeFilter = DisplayFilter.Parse(DisplayFilterText);
            FilterErrorMessage = null;
            RebuildFilteredPackets();
        }
        catch (DisplayFilterException ex)
        {
            FilterErrorMessage = ex.Message;
        }
    }

    [RelayCommand]
    private void ClearFilter()
    {
        DisplayFilterText = string.Empty;
        ApplyFilter();
    }

    private void RebuildFilteredPackets()
    {
        FilteredPackets.Clear();
        foreach (var packet in Packets)
            if (_activeFilter.Matches(packet))
                FilteredPackets.Add(packet);

        UpdateStatusMessage();
    }

    /// <summary>
    /// Ouvre une fenetre affichant la conversation TCP reconstituee du paquet selectionne.
    /// Pragmatique plutot que puriste MVVM : le ViewModel instancie directement la fenetre,
    /// pour eviter la machinerie d'un service de navigation pour un seul cas d'usage.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanFollowTcpStream))]
    private void FollowTcpStream()
    {
        if (SelectedPacket?.TcpStreamIndex is not { } streamIndex)
            return;

        var stream = _captureService.StreamTracker.GetStream(streamIndex);
        if (stream is null)
            return;

        var window = new TcpStreamWindow
        {
            DataContext = new TcpStreamWindowViewModel(stream)
        };
        window.Show();
    }

    private bool CanFollowTcpStream() => SelectedPacket?.TcpStreamIndex is not null;
    
    /// <summary>Ouvre la fenetre de statistiques en direct (paquets/s, repartition protocole, top talkers).</summary>
    [RelayCommand]
    private void OpenStats()
    {
        var window = new StatsWindow
        {
            DataContext = new StatsWindowViewModel(_captureService)
        };
        window.Show();
    }

    private void UpdateStatusMessage()
    {
        StatusMessage = FilteredPackets.Count == Packets.Count
            ? $"{Packets.Count} paquet(s) capturé(s)"
            : $"{FilteredPackets.Count} / {Packets.Count} paquet(s) affiché(s) (filtre actif)";
    }

    partial void OnIsCapturingChanged(bool value)
    {
        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
    }

    partial void OnSelectedInterfaceChanged(ICaptureDevice? value)
    {
        StartCommand.NotifyCanExecuteChanged();
    }
}