using Avalonia.Controls;
using Avalonia.Interactivity;
using MiniWireshark.Gui.ViewModels;

namespace MiniWireshark.Gui.Views;

public partial class StatsWindow : Window
{
    public StatsWindow()
    {
        InitializeComponent();
        Closed += (_, _) => (DataContext as StatsWindowViewModel)?.Dispose();
    }

    private void OnCloseClick(object? sender, RoutedEventArgs e) => Close();
}

