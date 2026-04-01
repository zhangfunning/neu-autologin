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
            await Services.MonitorService.StartAsync(cancellationToken);
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
            Services.Logger.ClearLogs();
        }
        catch
        {
        }
    }
}
