using System.Collections.Generic;

namespace MiniWireshark.Gui.ViewModels;

public sealed class PacketDetailNode
{
    public string Header { get; }
    public List<PacketDetailNode> Children { get; } = new();
    
    public PacketDetailNode(string header) => Header = header;

    public PacketDetailNode Add(string header)
    {
        var child = new PacketDetailNode(header);
        Children.Add(child);
        return child;
    }
}

