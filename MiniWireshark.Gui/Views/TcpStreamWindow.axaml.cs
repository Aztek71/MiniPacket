using Avalonia.Controls;
using Avalonia.Interactivity;

namespace MiniWireshark.Gui.Views;

public partial class TcpStreamWindow : Window
{
    public TcpStreamWindow()
    {
        InitializeComponent();
    }

    private void OnCloseClick(object? sender, RoutedEventArgs e) => Close();
}