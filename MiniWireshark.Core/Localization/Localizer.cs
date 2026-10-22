using System.ComponentModel;
using System.Globalization;
using Microsoft.VisualBasic;

namespace MiniWireshark.Core.Localization;

public enum Language { French, English }

public sealed class Localizer : INotifyPropertyChanged
{
    public static Localizer Instance { get; } = new();

    private static readonly CultureInfo FrenchCulture = CultureInfo.GetCultureInfo("fr-FR");
    private static readonly CultureInfo EnglishCulture = CultureInfo.GetCultureInfo("en-US");

    public event PropertyChangedEventHandler? PropertyChanged;

    public event Action? LanguageChanged;

    public Language Language { get; private set;} = Language.French;

    public CultureInfo Culture => Language == Language.English ? EnglishCulture : FrenchCulture;

    public void SetLanguage(Language language)
    {
        if (language == Language)
            return;
        
        Language = language;

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        LanguageChanged?.Invoke();
    }

    public string this[string key] => Get(key);

    public string Get(string key)
    {
        var table = Language == Language.English ? Strings.English : Strings.French;
        if (table.TryGetValue(key, out var text))
            return text;
        
        return Strings.French.TryGetValue(key, out var fallback) ? fallback : key;
    }

    public static string T(string key) => Instance.Get(key);

    public static string T(string key, params object?[] args) =>
        string.Format(Instance.Culture, Instance.Get(key), args);
    
    public static string Code(Language language) => language == Language.English ? "en" : "fr";

    public static Language? FromCode(string? code)
    {
        string? two = code?.Trim().ToLowerInvariant();
        if (two is null || two.Length < 2)
            return null;
        
        return two[..2] switch
        {
            "fr" => Language.French,
            "en" => Language.English,
            _ => null
        };
    }
}