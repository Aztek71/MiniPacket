namespace MiniWireshark.Core.Localization;

internal static class Strings
{
    public static readonly IReadOnlyDictionary<string, string> French = new Dictionary<string, string>
    {
        // Barre d'outils
        ["toolbar_start"] = "▶ Démarrer",
        ["toolbar_stop"] = "■ Arrêter",
        ["toolbar_stats"] = "📊 Statistiques",
        ["toolbar_interface_placeholder"] = "Choisis une interface réseau",
        ["toolbar_bpf_watermark"] = "Filtre BPF capture (ex: tcp port 443)",
        ["toolbar_language_tip"] = "Langue",

        // Filtres
        ["filter_app_placeholder"] = "Application (filtre)",
        ["filter_app_refresh_tip"] = "Actualiser la liste des applications",
        ["filter_display_watermark"] = "Filtre display (ex: tcp.port == 443 and ip.addr == 192.168.1.8)",
        ["filter_apply"] = "Appliquer",
        ["filter_clear"] = "Effacer",
        ["filter_follow_stream"] = "Suivre le flux TCP",
        ["app_all"] = "(toutes les applications)",

        // Recherche
        ["search_watermark"] = "Rechercher dans la liste…",
        ["search_in_content"] = "Dans le contenu",
        ["search_previous_tip"] = "Précédent (Maj+F3)",
        ["search_next_tip"] = "Suivant (F3)",
        ["search_empty"] = "Saisis un texte à rechercher.",
        ["search_none"] = "Aucun résultat.",
        ["search_result"] = "{0} / {1}",
        ["search_wrapped"] = "retour au début",

        // Colonnes de la liste
        ["col_no"] = "No.",
        ["col_time"] = "Heure",
        ["col_source"] = "Source",
        ["col_destination"] = "Destination",
        ["col_protocol"] = "Protocole",
        ["col_process"] = "Processus",
        ["col_length"] = "Long.",
        ["col_info"] = "Info",
        ["footer_total"] = "Total capturé : {0} paquet(s)",

        // Messages d'etat
        ["status_hint"] = "Sélectionne une interface puis clique sur Démarrer.",
        ["status_capturing"] = "Capture en cours sur {0}...",
        ["status_start_error"] = "Erreur au démarrage : {0}",
        ["status_captured"] = "{0} paquet(s) capturé(s)",
        ["status_filtered"] = "{0} / {1} paquet(s) affiché(s) (filtre actif)",

        // Panneau de detail
        ["detail_process"] = "Processus : {0}",
        ["detail_anomalies"] = "Analyse : {0} anomalie(s) détectée(s)",
        ["severity_error"] = "Erreur",
        ["severity_warning"] = "Attention",
        ["severity_info"] = "Info",

        // Fenetre de statistiques
        ["stats_title"] = "Statistiques en direct",
        ["stats_packets"] = "Paquets",
        ["stats_volume"] = "Volume",
        ["stats_tcp_streams"] = "Flux TCP",
        ["stats_pps"] = "Paquets/s",
        ["stats_chart_title"] = "Paquets par seconde (dernière minute)",
        ["stats_protocols"] = "Répartition par protocole",
        ["stats_talkers"] = "Top talkers (par volume)",
        ["stats_close"] = "Fermer",

        // Unites d'octets
        ["unit_b"] = "o",
        ["unit_kb"] = "Ko",
        ["unit_mb"] = "Mo",
        ["unit_gb"] = "Go",
    };

    public static readonly IReadOnlyDictionary<string, string> English = new Dictionary<string, string>
    {
        // Toolbar
        ["toolbar_start"] = "▶ Start",
        ["toolbar_stop"] = "■ Stop",
        ["toolbar_stats"] = "📊 Statistics",
        ["toolbar_interface_placeholder"] = "Choose a network interface",
        ["toolbar_bpf_watermark"] = "Capture BPF filter (e.g. tcp port 443)",
        ["toolbar_language_tip"] = "Language",

        // Filters
        ["filter_app_placeholder"] = "Application (filter)",
        ["filter_app_refresh_tip"] = "Refresh the application list",
        ["filter_display_watermark"] = "Display filter (e.g. tcp.port == 443 and ip.addr == 192.168.1.8)",
        ["filter_apply"] = "Apply",
        ["filter_clear"] = "Clear",
        ["filter_follow_stream"] = "Follow TCP stream",
        ["app_all"] = "(all applications)",

        // Search
        ["search_watermark"] = "Search the packet list…",
        ["search_in_content"] = "In payload",
        ["search_previous_tip"] = "Previous (Shift+F3)",
        ["search_next_tip"] = "Next (F3)",
        ["search_empty"] = "Type some text to search for.",
        ["search_none"] = "No results.",
        ["search_result"] = "{0} / {1}",
        ["search_wrapped"] = "wrapped around",

        // List columns
        ["col_no"] = "No.",
        ["col_time"] = "Time",
        ["col_source"] = "Source",
        ["col_destination"] = "Destination",
        ["col_protocol"] = "Protocol",
        ["col_process"] = "Process",
        ["col_length"] = "Len.",
        ["col_info"] = "Info",
        ["footer_total"] = "Total captured: {0} packet(s)",

        // Status messages
        ["status_hint"] = "Select an interface, then click Start.",
        ["status_capturing"] = "Capturing on {0}...",
        ["status_start_error"] = "Failed to start: {0}",
        ["status_captured"] = "{0} packet(s) captured",
        ["status_filtered"] = "{0} / {1} packet(s) shown (filter active)",

        // Detail pane
        ["detail_process"] = "Process: {0}",
        ["detail_anomalies"] = "Analysis: {0} issue(s) detected",
        ["severity_error"] = "Error",
        ["severity_warning"] = "Warning",
        ["severity_info"] = "Info",

        // Statistics window
        ["stats_title"] = "Live statistics",
        ["stats_packets"] = "Packets",
        ["stats_volume"] = "Volume",
        ["stats_tcp_streams"] = "TCP streams",
        ["stats_pps"] = "Packets/s",
        ["stats_chart_title"] = "Packets per second (last minute)",
        ["stats_protocols"] = "Protocol breakdown",
        ["stats_talkers"] = "Top talkers (by volume)",
        ["stats_close"] = "Close",

        // Byte units
        ["unit_b"] = "B",
        ["unit_kb"] = "KB",
        ["unit_mb"] = "MB",
        ["unit_gb"] = "GB",
    };
}