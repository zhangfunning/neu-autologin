namespace NEUNetworkAutoLogin.Services;

public sealed class AppContextServices
{
    public AppContextServices()
    {
        Paths = new AppPaths();
        Logger = new AppLogger(Paths);
        SettingsStore = new JsonSettingsStore(Paths, Logger);
        CredentialStore = new CredentialStore(Paths, Logger);
        StartupManager = new StartupManager(Paths);
        ProbeService = new NetworkProbeService();
        PortalLoginClient = new PortalLoginClient(Paths);
        MonitorService = new MonitorService(Logger, SettingsStore, CredentialStore, ProbeService, PortalLoginClient);
    }

    public AppPaths Paths { get; }
    public AppLogger Logger { get; }
    public JsonSettingsStore SettingsStore { get; }
    public CredentialStore CredentialStore { get; }
    public StartupManager StartupManager { get; }
    public NetworkProbeService ProbeService { get; }
    public PortalLoginClient PortalLoginClient { get; }
    public MonitorService MonitorService { get; }
}
