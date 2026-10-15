using Avalonia.Media;

namespace MiniWireshark.Gui.ViewModels;

/// <summary>Un morceau de conversation TCP pret pour l'affichage (texte + couleur selon le sens).</summary>
public sealed class TcpStreamChunkDisplay
{
    public required string Text { get; init; }
    public required IBrush Foreground { get; init; }
    public required string DirectionLabel { get; init; }
}