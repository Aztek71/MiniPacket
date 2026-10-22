using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MiniWireshark.Core.Localization;

public static class LanguageSettings
{
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MiniWireshark", "settings.json");
    
    public static Language? Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return null;
            
            var root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
            return Localizer.FromCode(root?["language"]?.GetValue<string>());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    public static void Save(string path, Language language)
    {
        try
        {
            JsonObject root = new();
            if (File.Exists(path))
            {
                try { root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject(); }
                catch (JsonException) { root = new JsonObject(); }
            }

            root["language"] = Localizer.Code(language);

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            
        }
    }

    public static Language DetectSystemLanguage() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("fr", StringComparison.OrdinalIgnoreCase)
            ? Language.French
            : Language.English;
}