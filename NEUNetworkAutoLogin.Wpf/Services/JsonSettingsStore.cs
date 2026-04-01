using System.Text.Json;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class JsonSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly AppPaths _paths;
    private readonly AppLogger _logger;

    public JsonSettingsStore(AppPaths paths, AppLogger logger)
    {
        _paths = paths;
        _logger = logger;
    }

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(_paths.SettingsPath))
            {
                var defaults = new AppSettings();
                Save(defaults);
                return defaults;
            }

            var raw = File.ReadAllText(_paths.SettingsPath);
            var settings = JsonSerializer.Deserialize<AppSettings>(raw, JsonOptions);
            return settings ?? new AppSettings();
        }
        catch (Exception ex)
        {
            _logger.Log($"Settings load failed, using defaults: {ex.Message}");
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(_paths.BaseDirectory);
        var json = JsonSerializer.Serialize(settings, JsonOptions);
        File.WriteAllText(_paths.SettingsPath, json);
    }
}
