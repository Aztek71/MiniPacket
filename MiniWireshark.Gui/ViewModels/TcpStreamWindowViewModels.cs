using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MiniWireshark.Core.Decryption;
using MiniWireshark.Core.Http;
using MiniWireshark.Core.Http.Http2;
using MiniWireshark.Core.Streams;

namespace MiniWireshark.Gui.ViewModels;

public enum StreamViewMode { Text, Hex, TlsSummary, Decrypted, Http }

/// <summary>
/// Vue instantanee d'un flux TCP reconstitue (snapshot pris a l'ouverture de la fenetre).
/// Affichages : texte brut, hexdump, resume TLS et - avec le fichier SSLKEYLOGFILE du navigateur - contenu dechiffre,
/// puis requetes/reponses HTTP decodees (HTTP/1.1 ou HTTP/2).
/// </summary>
public partial class TcpStreamWindowViewModel : ObservableObject
{
    // Au-dela, un TextBlock unique devient tres lent : on tronque l'affichage (pas les donnees).
    private const int MaxDisplayedBytesPerChunk = 16 * 1024;

    // Memorise d'une fenetre a l'autre : on ne retape pas le chemin a chaque flux.
    private static string? _lastKeyLogPath;

    private readonly TcpStream _stream;
    private readonly IReadOnlyList<TcpStreamDataChunk> _dataChunks;
    private readonly TlsStreamInfo? _tls;
    private readonly string _traffic;

    private TlsDecryptionResult? _decrypted;
    private HttpConversation? _http;
    private string _httpProtocol = "HTTP";
    private bool _clientIsEndpointA;
    private StreamViewMode _viewMode;
    private IReadOnlyList<TcpStreamChunkDisplay> _chunks = Array.Empty<TcpStreamChunkDisplay>();
    private string _summary = string.Empty;

    [ObservableProperty]
    private string _keyLogPath = string.Empty;

    [ObservableProperty]
    private string _decryptStatus = string.Empty;

    public string Title { get; }
    public bool IsTls => _tls is not null;
    public bool IsDecrypted => _decrypted?.Success == true;

    /// <summary>Vrai si le flux (en clair ou dechiffre) est du HTTP dont on a pu lire au moins un message.</summary>
    public bool HasHttp => _http is { Messages.Count: > 0 };

    public string Summary
    {
        get => _summary;
        private set => SetProperty(ref _summary, value);
    }

    public StreamViewMode ViewMode
    {
        get => _viewMode;
        private set
        {
            if (SetProperty(ref _viewMode, value))
                RebuildChunks();
        }
    }

    public IReadOnlyList<TcpStreamChunkDisplay> Chunks
    {
        get => _chunks;
        private set => SetProperty(ref _chunks, value);
    }

    public TcpStreamWindowViewModel(TcpStream stream)
    {
        _stream = stream;
        Title = $"Flux TCP #{stream.StreamIndex} : {stream.EndpointA} <-> {stream.EndpointB}";

        _dataChunks = TcpStreamReassembler.BuildDataChunks(stream);
        _tls = TlsStreamAnalyzer.Analyze(_dataChunks);

        long bytesA = _dataChunks.Where(c => c.FromEndpointA).Sum(c => (long)c.Data.Length);
        long bytesB = _dataChunks.Where(c => !c.FromEndpointA).Sum(c => (long)c.Data.Length);
        _traffic = $"{stream.EndpointA} \u2192 {FormatBytes(bytesA)}   |   {stream.EndpointB} \u2192 {FormatBytes(bytesB)}";

        // Flux non chiffre : si c'est du HTTP/1.x, on le decode directement.
        if (_tls is null)
            TryDecodePlainHttp();

        _summary = _tls is not null ? BuildTlsSummary()
            : HasHttp ? $"{_httpProtocol} : {_http!.Messages.Count(m => m.FromClient)} requête(s).   {_traffic}"
            : _traffic;

        _viewMode = _tls is not null ? StreamViewMode.TlsSummary : HasHttp ? StreamViewMode.Http : StreamViewMode.Text;
        RebuildChunks();

        // Si la variable d'environnement SSLKEYLOGFILE est definie (ou un chemin deja saisi), on tente tout de suite.
        KeyLogPath = _lastKeyLogPath ?? Environment.GetEnvironmentVariable("SSLKEYLOGFILE") ?? string.Empty;
        if (IsTls && File.Exists(KeyLogPath))
            TryDecrypt();
    }

    /// <summary>Flux non chiffre : si c'est du HTTP/1.x, on le decode directement depuis les octets reassembles.</summary>
    private void TryDecodePlainHttp()
    {
        byte[] a = TcpDirectionReassembler.Reassemble(_stream, true).Data;
        byte[] b = TcpDirectionReassembler.Reassemble(_stream, false).Data;

        bool aIsClient = Http1Decoder.LooksLikeHttp1(a);
        if (!aIsClient && !Http1Decoder.LooksLikeHttp1(b))
            return;

        _clientIsEndpointA = aIsClient;
        _httpProtocol = "HTTP/1.1";
        _http = aIsClient ? Http1Decoder.Decode(a, b) : Http1Decoder.Decode(b, a);
    }

    [RelayCommand]
    private void ShowTlsSummary() => ViewMode = StreamViewMode.TlsSummary;

    [RelayCommand]
    private void ShowText() => ViewMode = StreamViewMode.Text;

    [RelayCommand]
    private void ShowHex() => ViewMode = StreamViewMode.Hex;

    [RelayCommand]
    private void ShowDecrypted() => ViewMode = StreamViewMode.Decrypted;

    [RelayCommand]
    private void ShowHttp() => ViewMode = StreamViewMode.Http;

    [RelayCommand]
    private void Decrypt() => TryDecrypt();

    private void TryDecrypt()
    {
        if (!IsTls)
        {
            DecryptStatus = "Ce flux n'est pas du TLS.";
            return;
        }

        if (string.IsNullOrWhiteSpace(KeyLogPath))
        {
            DecryptStatus = "Indique le fichier SSLKEYLOGFILE du navigateur.";
            return;
        }

        KeyLog keyLog;
        try
        {
            // Le fichier est relu a chaque fois : le navigateur y ajoute des lignes en continu.
            keyLog = KeyLog.Load(KeyLogPath.Trim().Trim('"'));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            DecryptStatus = $"Fichier de clés illisible : {ex.Message}";
            return;
        }

        _lastKeyLogPath = KeyLogPath;
        _http = null;
        _decrypted = TlsSessionDecryptor.Decrypt(_stream, keyLog);
        OnPropertyChanged(nameof(IsDecrypted));

        if (!_decrypted.Success)
        {
            OnPropertyChanged(nameof(HasHttp));
            DecryptStatus = _decrypted.Error ?? "Échec du déchiffrement.";
            return;
        }

        // Le protocole negocie (ALPN) dit ce que contiennent les octets dechiffres ; sans ALPN, on reconnait
        // le HTTP/1.x a sa forme (une methode suivie d'un espace).
        byte[] clientBytes = _decrypted.ApplicationData(fromClient: true);
        byte[] serverBytes = _decrypted.ApplicationData(fromClient: false);
        _clientIsEndpointA = _decrypted.ClientIsEndpointA;

        if (_decrypted.Alpn == "h2")
        {
            _httpProtocol = "HTTP/2";
            _http = Http2Decoder.Decode(clientBytes, serverBytes);
        }
        else if (Http1Decoder.LooksLikeHttp1(clientBytes))
        {
            _httpProtocol = "HTTP/1.1";
            _http = Http1Decoder.Decode(clientBytes, serverBytes);
        }
        OnPropertyChanged(nameof(HasHttp));

        string alpn = _decrypted.Alpn is { } protocol ? $", protocole {protocol}" : string.Empty;
        string notes = _decrypted.Notes.Count > 0 ? " — " + string.Join(" ", _decrypted.Notes) : string.Empty;
        DecryptStatus = $"Déchiffré ({_decrypted.CipherSuite}{alpn}){notes}";

        string server = _tls?.ServerName is { } sni ? $" vers {sni}" : string.Empty;
        string http = HasHttp ? $" — {_httpProtocol} : {_http!.Messages.Count(m => m.FromClient)} requête(s)" : string.Empty;
        Summary = $"Connexion TLS{server} déchiffrée{http}.   {_traffic}";

        ViewMode = HasHttp ? StreamViewMode.Http : StreamViewMode.Decrypted;
        RebuildChunks();   // si on etait deja dans ce mode, le setter ne reconstruit pas
    }

    private void RebuildChunks()
    {
        Chunks = ViewMode switch
        {
            StreamViewMode.TlsSummary => BuildTlsChunks(),
            StreamViewMode.Hex => BuildHexChunks(),
            StreamViewMode.Decrypted => BuildDecryptedChunks(),
            StreamViewMode.Http => BuildHttpChunks(),
            _ => BuildTextChunks()
        };
    }

    private List<TcpStreamChunkDisplay> BuildTextChunks()
    {
        var list = new List<TcpStreamChunkDisplay>();
        foreach (var chunk in TcpStreamReassembler.BuildConversationChunks(_stream))
        {
            string text = chunk.Text.Length > MaxDisplayedBytesPerChunk
                ? chunk.Text[..MaxDisplayedBytesPerChunk]
                  + $"\n... {chunk.Text.Length - MaxDisplayedBytesPerChunk} caractères supplémentaires non affichés"
                : chunk.Text;
            list.Add(Display(chunk.FromEndpointA, text));
        }
        return list;
    }

    private List<TcpStreamChunkDisplay> BuildHexChunks()
    {
        var list = new List<TcpStreamChunkDisplay>();
        foreach (var chunk in _dataChunks)
            list.Add(Display(chunk.FromEndpointA, FormatHexDump(chunk.Data)));
        return list;
    }

    private List<TcpStreamChunkDisplay> BuildTlsChunks()
    {
        var list = new List<TcpStreamChunkDisplay>();
        if (_tls is null)
            return list;

        foreach (var record in _tls.Records)
        {
            string text = !record.IsApplicationData && record.ByteCount > 0
                ? $"{record.Description} ({record.ByteCount} octets)"
                : record.Description;
            list.Add(Display(record.FromEndpointA, text));
        }
        return list;
    }

    /// <summary>
    /// Contenu dechiffre : les enregistrements Application Data consecutifs d'un meme sens sont recolles pour que
    /// une reponse repartie sur plusieurs enregistrements se lise d'un seul tenant ; le reste (handshake, alertes)
    /// s'affiche en une ligne descriptive.
    /// </summary>
    private List<TcpStreamChunkDisplay> BuildDecryptedChunks()
    {
        var list = new List<TcpStreamChunkDisplay>();
        if (_decrypted is not { Success: true } result)
            return list;

        bool isHttp2 = result.Alpn == "h2";
        var pending = new List<byte>();
        bool pendingFromA = false;

        void Flush()
        {
            if (pending.Count == 0)
                return;

            byte[] data = pending.ToArray();
            string text = isHttp2
                ? "[HTTP/2 : trames binaires brutes, voir le bouton HTTP/2 pour les messages décodés]\n" + FormatHexDump(data)
                : DecodePrintable(data);
            list.Add(Display(pendingFromA, text));
            pending.Clear();
        }

        foreach (var record in result.Records)
        {
            if (record.WasEncrypted && record.ContentType == 23)
            {
                if (pending.Count > 0 && pendingFromA != record.FromEndpointA)
                    Flush();

                pendingFromA = record.FromEndpointA;
                pending.AddRange(record.Data);
            }
            else
            {
                Flush();
                list.Add(Display(record.FromEndpointA, record.Description));
            }
        }

        Flush();
        return list;
    }

    /// <summary>Une entree par requete ou reponse HTTP : ligne de depart, en-tetes, corps (decompresse si besoin).</summary>
    private List<TcpStreamChunkDisplay> BuildHttpChunks()
    {
        var list = new List<TcpStreamChunkDisplay>();
        if (_http is null)
            return list;

        string unit = _httpProtocol == "HTTP/2" ? "flux" : "échange";

        foreach (var message in _http.Messages)
        {
            var sb = new StringBuilder();
            sb.Append('[').Append(unit).Append(' ').Append(message.StreamId).Append("] ").AppendLine(message.StartLine);

            // Les pseudo-en-tetes HTTP/2 (:method, :path...) sont deja resumes dans la ligne de depart.
            foreach (var (name, value) in message.Headers)
                if (!name.StartsWith(':'))
                    sb.Append(name).Append(": ").AppendLine(value);

            if (message.Trailers.Count > 0)
            {
                sb.AppendLine("Trailers :");
                foreach (var (name, value) in message.Trailers)
                    sb.Append("  ").Append(name).Append(": ").AppendLine(value);
            }

            AppendBody(sb, message);

            bool fromA = message.FromClient == _clientIsEndpointA;
            list.Add(Display(fromA, sb.ToString().TrimEnd()));
        }

        if (_http.ConnectionEvents.Count > 0)
            list.Add(Note($"Connexion {_httpProtocol}", string.Join("\n", _http.ConnectionEvents), Brushes.Gray));

        if (_http.Problems.Count > 0)
            list.Add(Note("Anomalies", string.Join("\n", _http.Problems), Brushes.Orange));

        return list;
    }

    private static void AppendBody(StringBuilder sb, HttpMessage message)
    {
        if (message.WireBodyLength == 0)
            return;

        sb.AppendLine();
        if (message.BodyNote is not null)
            sb.Append('(').Append(message.BodyNote).AppendLine(")");

        if (LooksLikeText(message))
        {
            sb.Append(Encoding.UTF8.GetString(message.Body, 0, Math.Min(message.Body.Length, MaxDisplayedBytesPerChunk)));
            if (message.Body.Length > MaxDisplayedBytesPerChunk)
                sb.Append($"\n... {message.Body.Length - MaxDisplayedBytesPerChunk} octets supplémentaires non affichés");
        }
        else
        {
            int preview = Math.Min(message.Body.Length, 256);
            sb.AppendLine($"(contenu binaire : {message.Body.Length} octets, {preview} premiers affichés)");
            sb.Append(FormatHexDump(message.Body.AsSpan(0, preview).ToArray()));
        }
    }

    /// <summary>Texte si le Content-Type l'annonce ; sinon, si les premiers octets ne contiennent aucun caractere de controle.</summary>
    private static bool LooksLikeText(HttpMessage message)
    {
        string type = (message.Header("content-type") ?? string.Empty).ToLowerInvariant();
        if (type.StartsWith("text/") || type.Contains("json") || type.Contains("xml") || type.Contains("javascript")
            || type.Contains("x-www-form-urlencoded") || type.Contains("svg"))
            return true;

        foreach (byte b in message.Body.Take(512))
            if (b < 0x20 && b != (byte)'\n' && b != (byte)'\r' && b != (byte)'\t')
                return false;

        return message.Body.Length > 0;
    }

    private string BuildTlsSummary()
    {
        string server = _tls!.ServerName is { } sni ? $" vers {sni}" : string.Empty;
        return $"Connexion TLS{server} : contenu chiffré, illisible sans les clés de session.   {_traffic}";
    }

    private TcpStreamChunkDisplay Display(bool fromEndpointA, string text) => new()
    {
        Text = text,
        Foreground = fromEndpointA ? Brushes.DodgerBlue : Brushes.IndianRed,
        DirectionLabel = fromEndpointA ? $"{_stream.EndpointA} \u2192" : $"{_stream.EndpointB} \u2192"
    };

    private static TcpStreamChunkDisplay Note(string label, string text, IBrush brush) => new()
    {
        Text = text,
        Foreground = brush,
        DirectionLabel = label
    };

    /// <summary>Texte lisible : les octets non imprimables deviennent un '.', comme dans Wireshark.</summary>
    private static string DecodePrintable(byte[] data)
    {
        int shown = Math.Min(data.Length, MaxDisplayedBytesPerChunk);
        var chars = new char[shown];
        for (int i = 0; i < shown; i++)
        {
            byte b = data[i];
            chars[i] = (b >= 0x20 && b < 0x7F) || b is (byte)'\n' or (byte)'\r' or (byte)'\t' ? (char)b : '.';
        }

        string text = new string(chars);
        return data.Length > shown ? text + $"\n... {data.Length - shown} octets supplémentaires non affichés" : text;
    }

    /// <summary>Format classique : offset, 16 octets en hexadecimal, puis colonne ASCII.</summary>
    private static string FormatHexDump(byte[] data)
    {
        int shown = Math.Min(data.Length, MaxDisplayedBytesPerChunk);
        var sb = new StringBuilder();

        for (int offset = 0; offset < shown; offset += 16)
        {
            int count = Math.Min(16, shown - offset);
            sb.Append(offset.ToString("x4")).Append("  ");

            for (int i = 0; i < 16; i++)
            {
                if (i < count) sb.Append(data[offset + i].ToString("x2")).Append(' ');
                else sb.Append("   ");
                if (i == 7) sb.Append(' ');
            }

            sb.Append(" |");
            for (int i = 0; i < count; i++)
            {
                byte b = data[offset + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.Append('|');

            if (offset + 16 < shown)
                sb.AppendLine();
        }

        if (data.Length > shown)
        {
            sb.AppendLine();
            sb.Append($"... {data.Length - shown} octets supplémentaires non affichés");
        }

        return sb.ToString();
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = { "o", "Ko", "Mo", "Go" };
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:0.#} {units[unit]}";
    }
}