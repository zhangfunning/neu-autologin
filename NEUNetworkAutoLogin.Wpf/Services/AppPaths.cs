namespace NEUNetworkAutoLogin.Services;

public sealed class AppPaths
{
    public AppPaths()
    {
        BaseDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NEUNetworkAutoLogin");

        LogsDirectory = Path.Combine(BaseDirectory, "logs");
        SettingsPath = Path.Combine(BaseDirectory, "settings.json");
        CredentialPath = Path.Combine(BaseDirectory, "credential.json");
        StartupShortcutPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            "NEUNetworkAutoLogin.lnk");
    }

    public string BaseDirectory { get; }
    public string LogsDirectory { get; }
    public string SettingsPath { get; }
    public string CredentialPath { get; }
    public string StartupShortcutPath { get; }
}
