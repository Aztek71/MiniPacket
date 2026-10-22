using System;
using Avalonia.Controls;
using Avalonia.Input;
using MiniWireshark.Gui.ViewModels;
using MiniWireshark.Models;

namespace MiniWireshark.Gui.Views;

public partial class MainWindow : Window
{
    private MainWindowViewModel? _viewModel;
    private TextBox? _searchTextBox;

    public MainWindow()
    {
        InitializeComponent();
        _searchTextBox = this.FindControl<TextBox>("SearchTextBox");

        // Le compilateur XAML d'Avalonia genere un champ par x:Name (DisplayFilterTextBox, SearchTextBox, PacketGrid).

        // Entree dans le champ de filtre display = appliquer, sans passer par le bouton.
        DisplayFilterTextBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && DataContext is MainWindowViewModel vm)
                vm.ApplyFilterCommand.Execute(null);
        };

        // Entree dans le champ de recherche = resultat suivant ; Maj+Entree = precedent.
        if (_searchTextBox is not null)
        {
            _searchTextBox.KeyDown += (_, e) =>
            {
                if (e.Key != Key.Enter || DataContext is not MainWindowViewModel vm)
                    return;

                if (e.KeyModifiers.HasFlag(KeyModifiers.Shift))
                    vm.FindPreviousCommand.Execute(null);
                else
                    vm.FindNextCommand.Execute(null);

                e.Handled = true;
            };
        }

        KeyDown += OnWindowKeyDown;
        DataContextChanged += OnDataContextChanged;
    }

    /// <summary>Raccourcis de toute la fenetre : Ctrl+F va au champ de recherche, F3 / Maj+F3 parcourent les resultats.</summary>
    private void OnWindowKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm)
            return;

        if (e.Key == Key.F && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            _searchTextBox?.Focus();
            _searchTextBox?.SelectAll();
            e.Handled = true;
        }
        else if (e.Key == Key.F3)
        {
            if (e.KeyModifiers.HasFlag(KeyModifiers.Shift))
                vm.FindPreviousCommand.Execute(null);
            else
                vm.FindNextCommand.Execute(null);

            e.Handled = true;
        }
    }

    // Le DataContext est affecte apres la construction de la fenetre (voir App.axaml.cs) : on s'abonne a ce moment-la.
    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_viewModel is not null)
            _viewModel.ScrollToPacketRequested -= OnScrollToPacketRequested;

        _viewModel = DataContext as MainWindowViewModel;

        if (_viewModel is not null)
            _viewModel.ScrollToPacketRequested += OnScrollToPacketRequested;
    }

    private void OnScrollToPacketRequested(CapturedPacket packet) =>
        this.FindControl<DataGrid>("PacketGrid")?.ScrollIntoView(packet, null);
}