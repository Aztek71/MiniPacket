using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MiniWireshark.Core;
using MiniWireshark.Core.Filtering;
using MiniWireshark.Core.Localization;
using MiniWireshark.Core.Search;
using MiniWireshark.Core.Streams;
using MiniWireshark.Gui.Views;
using MiniWireshark.Models;
using SharpPcap;

namespace MiniWireshark.Gui.ViewModels;

/// <summary>Une entree du selecteur de langue : le nom est affiche tel quel, dans sa propre langue.</summary>
public sealed record LanguageOption(Language Language, string Name);

public partial class MainWindowViewModel : ViewModelBase
{
    /// <summary>Ce que dit actuellement la barre d'etat : on garde l'etat et non le texte, pour pouvoir le retraduire.</summary>
    private enum StatusKind { Hint, Capturing, StartError, Counts }

    private readonly PacketCaptureService _captureService = new();
    private readonly DispatcherTimer _anomalyTimer;

    /// <summary>Le filtre display actuellement actif — DisplayFilter.AcceptAll si aucun filtre n'est appliqué.</summary>
    private IPacketFilter _activeFilter = DisplayFilter.AcceptAll;

    private StatusKind _statusKind = StatusKind.Hint;
    private string _statusArgument = string.Empty;
    private bool _suppressApplicationFilter;
    private LanguageOption _selectedLanguageOption;

    /// <summary>Interfaces réseau disponibles, remplies une fois au démarrage.</summary>
    public ObservableCollection<ICaptureDevice> Interfaces { get; } = new();

    /// <summary>Tous les paquets capturés, sans filtrage — sert de source pour le recalcul du filtre.</summary>
    public ObservableCollection<CapturedPacket> Packets { get; } = new();

    /// <summary>Les paquets après application du filtre display — c'est ce que le DataGrid affiche.</summary>
    public ObservableCollection<CapturedPacket> FilteredPackets { get; } = new();

    /// <summary>Détail du paquet sélectionné — équivalent du panneau "Packet Details".</summary>
    public ObservableCollection<PacketDetailNode> DetailNodes { get; } = new();

    /// <summary>Applications ayant des connexions reseau : un clic filtre la liste sur leur trafic. L'entree 0 = "toutes".</summary>
    public ObservableCollection<string> Applications { get; } = new() { Localizer.T("app_all") };

    public IReadOnlyList<LanguageOption> LanguageOptions { get; } = new[]
    {
        new LanguageOption(Language.French, "Français"),
        new LanguageOption(Language.English, "English")
    };

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
    private string _statusMessage = Localizer.T("status_hint");

    [ObservableProperty]
    private string _footerText = Localizer.T("footer_total", 0);

    [ObservableProperty]
    private CapturedPacket? _selectedPacket;

    [ObservableProperty]
    private string? _selectedApplication;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private bool _searchInContent;

    [ObservableProperty]
    private string _searchStatus = string.Empty;

    /// <summary>Demande a la vue de faire defiler la liste jusqu'a ce paquet (la vue possede le DataGrid).</summary>
    public event Action<CapturedPacket>? ScrollToPacketRequested;

    public MainWindowViewModel()
    {
        foreach (var device in PacketCaptureService.ListDevices())
            Interfaces.Add(device);

        _selectedLanguageOption = Localizer.Instance.Language == Language.English ? LanguageOptions[1] : LanguageOptions[0];

        _captureService.OnPacketCaptured += packet =>
        {
            // La capture arrive sur le thread de SharpPcap : on repasse sur le thread UI Avalonia
            // avant de toucher aux ObservableCollection, sous peine d'exception cross-thread.
            Dispatcher.UIThread.Post(() =>
            {
                Packets.Add(packet);
                if (_activeFilter.Matches(packet))
                    FilteredPackets.Add(packet);

                SetStatus(StatusKind.Counts);
            });
        };

        // Un SYN sans reponse ne se repere qu'apres coup : on verifie une fois par seconde pendant la capture.
        _anomalyTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _anomalyTimer.Tick += (_, _) => FlagExpiredSyns();
        _anomalyTimer.Start();

        // Des paquets deja affiches peuvent etre rattaches a leur processus apres coup (voir OnProcessesResolved).
        _captureService.Processes.ProcessesResolved += OnProcessesResolved;

        Localizer.Instance.LanguageChanged += OnLanguageChanged;

        RefreshApplications();   // liste initiale : les applications qui ont deja des connexions
    }

    // ----- Langue -----

    public LanguageOption SelectedLanguageOption
    {
        get => _selectedLanguageOption;
        set
        {
            if (!SetProperty(ref _selectedLanguageOption, value) || value is null)
                return;

            Localizer.Instance.SetLanguage(value.Language);
            LanguageSettings.Save(LanguageSettings.DefaultPath, value.Language);
        }
    }

    /// <summary>
    /// Les libelles XAML se rafraichissent tout seuls (liaisons sur l'indexeur du Localizer). Restent les textes
    /// calcules ici : barre d'etat, entree "toutes les applications", panneau de detail, etat de la recherche.
    /// </summary>
    private void OnLanguageChanged()
    {
        RefreshStatusMessage();

        // Retraduire l'entree 0 de la liste des applications ne doit surtout pas declencher un filtre.
        _suppressApplicationFilter = true;
        try
        {
            bool allWasSelected = SelectedApplication is not null && SelectedApplication == Applications[0];
            Applications[0] = Localizer.T("app_all");
            if (allWasSelected)
                SelectedApplication = null;
        }
        finally
        {
            _suppressApplicationFilter = false;
        }

        SearchStatus = string.Empty;
        RebuildDetails();
    }

    // ----- Barre d'etat -----

    private void SetStatus(StatusKind kind, string argument = "")
    {
        _statusKind = kind;
        _statusArgument = argument;
        RefreshStatusMessage();
    }

    private void RefreshStatusMessage()
    {
        StatusMessage = _statusKind switch
        {
            StatusKind.Capturing => Localizer.T("status_capturing", _statusArgument),
            StatusKind.StartError => Localizer.T("status_start_error", _statusArgument),
            StatusKind.Counts => FilteredPackets.Count == Packets.Count
                ? Localizer.T("status_captured", Packets.Count)
                : Localizer.T("status_filtered", FilteredPackets.Count, Packets.Count),
            _ => Localizer.T("status_hint")
        };

        FooterText = Localizer.T("footer_total", Packets.Count);
    }

    // ----- Selection et detail -----

    partial void OnSelectedPacketChanged(CapturedPacket? value) => RebuildDetails();

    private void RebuildDetails()
    {
        DetailNodes.Clear();

        if (SelectedPacket is { } packet)
            foreach (var node in PacketDetailBuilder.Build(packet))
                DetailNodes.Add(node);

        FollowTcpStreamCommand.NotifyCanExecuteChanged();
    }

    // ----- Capture -----

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
            SetStatus(StatusKind.Capturing, SelectedInterface.Description ?? SelectedInterface.Name);
        }
        catch (Exception ex)
        {
            SetStatus(StatusKind.StartError, ex.Message);
        }
    }

    private bool CanStart() => !IsCapturing && SelectedInterface is not null;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void Stop()
    {
        _captureService.Stop();
        IsCapturing = false;
        SetStatus(StatusKind.Counts);
    }

    private bool CanStop() => IsCapturing;

    // ----- Filtre display -----

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
        SelectedApplication = null;   // la liste des applications se remet sur "aucun filtre"
        DisplayFilterText = string.Empty;
        ApplyFilter();
    }

    private void RebuildFilteredPackets()
    {
        FilteredPackets.Clear();
        foreach (var packet in Packets)
            if (_activeFilter.Matches(packet))
                FilteredPackets.Add(packet);

        SetStatus(StatusKind.Counts);
    }

    // ----- Recherche dans la liste -----

    partial void OnSearchTextChanged(string value) => SearchStatus = string.Empty;

    [RelayCommand]
    private void FindNext() => FindMatch(forward: true);

    [RelayCommand]
    private void FindPrevious() => FindMatch(forward: false);

    /// <summary>
    /// Deplace la selection sur la correspondance suivante (ou precedente) dans la liste affichee, avec retour au debut
    /// ou a la fin. La recherche est refaite a chaque appel : la liste grossit pendant la capture.
    /// </summary>
    private void FindMatch(bool forward)
    {
        string query = (SearchText ?? string.Empty).Trim();
        if (query.Length == 0)
        {
            SearchStatus = Localizer.T("search_empty");
            return;
        }

        var matches = PacketSearch.FindAll(FilteredPackets, query, SearchInContent);
        if (matches.Count == 0)
        {
            SearchStatus = Localizer.T("search_none");
            return;
        }

        int current = -1;
        if (SelectedPacket is { } selected)
        {
            int index = PacketListSearch.BinarySearchByNumber(FilteredPackets, selected.Number);
            if (index >= 0)
                current = index;
        }

        int position = PacketSearch.NextPosition(matches, current, forward);
        int target = matches[position];

        bool wrapped = current >= 0 && (forward ? target <= current : target >= current);
        SearchStatus = Localizer.T("search_result", position + 1, matches.Count)
                       + (wrapped ? " — " + Localizer.T("search_wrapped") : string.Empty);

        var packet = FilteredPackets[target];
        SelectedPacket = packet;
        ScrollToPacketRequested?.Invoke(packet);
    }

    // ----- Flux TCP et statistiques -----

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

    // ----- Anomalies detectees apres coup -----

    /// <summary>Marque les SYN restes sans reponse. Execute sur le thread UI : la liste reagit au changement.</summary>
    private void FlagExpiredSyns()
    {
        if (!IsCapturing)
            return;

        foreach (var (packet, anomaly) in _captureService.Analyzer.ExpirePendingSyns())
            packet.AddAnomaly(anomaly);
    }

    // ----- Filtre par application -----

    private static bool IsAllApplications(string? value) =>
        string.IsNullOrEmpty(value) || value == Localizer.T("app_all");

    partial void OnSelectedApplicationChanged(string? value)
    {
        if (_suppressApplicationFilter)
            return;

        // Choisir une application revient a appliquer le filtre display "process.name == ...".
        DisplayFilterText = IsAllApplications(value) ? string.Empty : $"process.name == \"{value}\"";
        ApplyFilter();
    }

    /// <summary>Relit la table des connexions du systeme et met a jour la liste des applications.</summary>
    [RelayCommand]
    private void RefreshApplications()
    {
        _captureService.Processes.RefreshNow();
        MergeApplications(_captureService.Processes.GetApplicationNames());
    }

    private void MergeApplications(IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            if (Applications.Contains(name))
                continue;

            // Insertion triee (apres l'entree de tete) : la liste ne saute pas sous le curseur quand elle s'enrichit.
            int index = 1;
            while (index < Applications.Count && string.Compare(Applications[index], name, StringComparison.OrdinalIgnoreCase) < 0)
                index++;
            Applications.Insert(index, name);
        }
    }

    /// <summary>
    /// Des paquets deja affiches viennent d'etre rattaches a un processus (leur connexion n'etait pas encore dans la
    /// table du systeme quand ils sont arrives). Evenement leve sur un thread du timer : on repasse sur le thread UI.
    /// </summary>
    private void OnProcessesResolved(IReadOnlyList<(CapturedPacket Packet, int Pid, string Name)> resolved)
    {
        Dispatcher.UIThread.Post(() =>
        {
            bool filtering = !ReferenceEquals(_activeFilter, DisplayFilter.AcceptAll);

            foreach (var (packet, pid, name) in resolved)
            {
                packet.SetProcess(pid, name);

                // Un filtre sur l'application ne laissait pas passer ces paquets tant que leur processus etait inconnu :
                // on les insere maintenant a leur place.
                if (filtering && _activeFilter.Matches(packet))
                    InsertIntoFilteredPackets(packet);
            }

            MergeApplications(_captureService.Processes.GetApplicationNames());
            SetStatus(StatusKind.Counts);
        });
    }

    private void InsertIntoFilteredPackets(CapturedPacket packet)
    {
        // Le paquet doit appartenir a la capture en cours (une nouvelle a pu demarrer entre-temps).
        int inCapture = PacketListSearch.BinarySearchByNumber(Packets, packet.Number);
        if (inCapture < 0 || !ReferenceEquals(Packets[inCapture], packet))
            return;

        int index = PacketListSearch.BinarySearchByNumber(FilteredPackets, packet.Number);
        if (index < 0)
            FilteredPackets.Insert(~index, packet);
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