using Avalonia.Controls;
using Avalonia.Input;
using MiniWireshark.Gui.ViewModels;

namespace MiniWireshark.Gui.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

		DisplayFilterTextBox.KeyDown += (_, e) =>
		{
			if (e.Key == Key.Enter && DataContext is MainWindowViewModel vm)
				vm.ApplyFilterCommand.Execute(null);
		};
    }
}

