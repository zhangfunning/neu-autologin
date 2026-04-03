using System.Windows;
using NEUNetworkAutoLogin.Services;

namespace NEUNetworkAutoLogin;

public partial class App : System.Windows.Application
{
    private readonly CancellationTokenSource _shutdownCts = new();

    public static AppContextServices Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        Services = new AppContextServices();
        Exit += OnExit;
        SessionEnding += (_, _) => _shutdownCts.Cancel();

        var backgroundMode = e.Args.Any(arg => arg.Equals("--background", StringComparison.OrdinalIgnoreCase));
        if (backgroundMode)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunBackgroundAsync(_shutdownCts.Token);
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    private async Task RunBackgroundAsync(CancellationToken cancellationToken)
    {
        try
        {
            var settings = Services.SettingsStore.Load();
            if (!settings.EnableBackgroundMonitor)
            {
                Services.Logger.Log("Background startup skipped because monitor option is disabled.");
                Shutdown();
                return;
            }

            var startResult = await Services.MonitorService.StartAsync(cancellationToken);
            if (startResult == MonitorService.StartResult.AlreadyRunningInAnotherProcess)
            {
                Services.Logger.Log("Background startup skipped because monitor is already running.");
                Shutdown();
                return;
            }
            if (startResult == MonitorService.StartResult.DisabledBySettings)
            {
                Services.Logger.Log("Background startup skipped because monitor option is disabled.");
                Shutdown();
                return;
            }
        }
        catch (Exception ex)
        {
            Services.Logger.Log($"Background startup failed: {ex.Message}");
            Shutdown();
            return;
        }

        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            await Services.MonitorService.StopAsync();
            Shutdown();
        }
    }

    private void OnExit(object? sender, ExitEventArgs e)
    {
        _shutdownCts.Cancel();
        try
        {
            Services.MonitorService.StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
        }

        try
        {
            Services.Logger.CleanupOldLogs(keepDays: 14);
        }
        catch
        {
        }
    }
}
