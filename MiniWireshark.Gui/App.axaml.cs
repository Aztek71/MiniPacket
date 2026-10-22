using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MiniWireshark.Core.Localization;
using MiniWireshark.Gui.ViewModels;
using MiniWireshark.Gui.Views;

namespace MiniWireshark.Gui;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Langue : le choix enregistre la derniere fois, sinon la langue de Windows. Avant la creation de la fenetre,
        // pour qu'elle s'affiche directement dans la bonne langue.
        Localizer.Instance.SetLanguage(
            LanguageSettings.Load(LanguageSettings.DefaultPath) ?? LanguageSettings.DetectSystemLanguage());

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel()
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}