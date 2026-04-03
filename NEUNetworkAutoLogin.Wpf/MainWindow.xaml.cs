using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using NEUNetworkAutoLogin.Models;
using NEUNetworkAutoLogin.Services;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace NEUNetworkAutoLogin;

public partial class MainWindow : Window
{
    private readonly AppContextServices _services;
    private readonly DispatcherTimer _refreshTimer;
    private readonly Forms.NotifyIcon _notifyIcon;
    private bool _allowExit;
    private bool _isLoadingUiModel;
    private int _monitorEnsureInProgress;
    private string _lastLogSnapshot = string.Empty;

    public MainWindow()
    {
        InitializeComponent();

        _services = App.Services;
        _notifyIcon = CreateNotifyIcon();

        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        _refreshTimer.Tick += (_, _) => RefreshUi();
        _refreshTimer.Start();

        LoadUiModel();
        RefreshUi();
    }

    private void LoadUiModel()
    {
        _isLoadingUiModel = true;
        try
        {
            var settings = _services.SettingsStore.Load();
            var credential = _services.CredentialStore.Load();

            UsernameBox.Text = credential.Username;
            PasswordBox.Password = credential.Password;
            PortalHostBox.Text = settings.PortalHost;
            ServiceBaseUrlBox.Text = settings.ServiceBaseUrl;
            MonitorEnabledCheckBox.IsChecked = settings.EnableBackgroundMonitor;
            StartupCheckBox.IsChecked = _services.StartupManager.IsEnabled();
        }
        finally
        {
            _isLoadingUiModel = false;
        }
    }

    private AppSettings CollectSettingsFromUi(bool requireCredential)
    {
        var portalHost = PortalHostBox.Text.Trim();
        var serviceBaseUrl = ServiceBaseUrlBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(portalHost) || string.IsNullOrWhiteSpace(serviceBaseUrl))
        {
            throw new InvalidOperationException("Portal Host 和 Service Base URL 不能为空。");
        }

        if (requireCredential &&
            (string.IsNullOrWhiteSpace(UsernameBox.Text) || string.IsNullOrWhiteSpace(PasswordBox.Password)))
        {
            throw new InvalidOperationException("账号和密码不能为空。");
        }

        var current = _services.SettingsStore.Load();
        current.PortalHost = portalHost;
        current.ServiceBaseUrl = serviceBaseUrl;
        current.EnableBackgroundMonitor = MonitorEnabledCheckBox.IsChecked == true;
        return current;
    }

    private CredentialModel CollectCredentialFromUi()
    {
        return new CredentialModel
        {
            Username = UsernameBox.Text.Trim(),
            Password = PasswordBox.Password
        };
    }

    private async Task SaveFromUiAsync(bool requireCredential)
    {
        var settings = CollectSettingsFromUi(requireCredential);
        _services.SettingsStore.Save(settings);
        _services.StartupManager.SetEnabled(StartupCheckBox.IsChecked == true);

        var hasCredential = !string.IsNullOrWhiteSpace(UsernameBox.Text) &&
                            !string.IsNullOrWhiteSpace(PasswordBox.Password);
        if (requireCredential || hasCredential)
        {
            _services.CredentialStore.Save(CollectCredentialFromUi());
        }

        if (!settings.EnableBackgroundMonitor && _services.MonitorService.IsRunning)
        {
            await _services.MonitorService.StopAsync();
            _services.Logger.Log("后台监控已关闭，已自动停止当前监控实例。");
        }

        _services.Logger.Log("配置已保存。");
    }

    private async Task ApplyMonitorSwitchAsync()
    {
        var settings = _services.SettingsStore.Load();
        var enableMonitor = MonitorEnabledCheckBox.IsChecked == true;
        settings.EnableBackgroundMonitor = enableMonitor;
        _services.SettingsStore.Save(settings);

        if (enableMonitor)
        {
            var startResult = await _services.MonitorService.StartAsync();
            if (startResult == MonitorService.StartResult.AlreadyRunningInAnotherProcess)
            {
                _services.Logger.Log("后台监控已由另一个进程运行。");
                return;
            }

            if (startResult == MonitorService.StartResult.DisabledBySettings)
            {
                _services.Logger.Log("后台监控启用失败：配置未启用。");
                return;
            }

            _services.Logger.Log("后台监控已开启。");
            return;
        }

        await _services.MonitorService.StopAsync();
        _services.Logger.Log("后台监控已关闭。");
    }

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(async () =>
        {
            await SaveFromUiAsync(requireCredential: false);
            SetStatus("配置已保存。");
            RefreshUi();
        });
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(async () =>
        {
            await SaveFromUiAsync(requireCredential: true);
            var settings = _services.SettingsStore.Load();
            var credential = _services.CredentialStore.Load();
            var context = await _services.ProbeService.ResolvePortalContextAsync(settings, CancellationToken.None);
            var effective = new AppSettings
            {
                AcId = context.AcId > 0 ? context.AcId : settings.AcId,
                PortalHost = string.IsNullOrWhiteSpace(context.PortalHost) ? settings.PortalHost : context.PortalHost,
                ServiceBaseUrl = settings.ServiceBaseUrl,
                EnableBackgroundMonitor = settings.EnableBackgroundMonitor,
                InitialDelaySeconds = settings.InitialDelaySeconds,
                RetryDelaySeconds = settings.RetryDelaySeconds,
                MaxAttempts = settings.MaxAttempts,
                MonitorIntervalSeconds = settings.MonitorIntervalSeconds,
                FailureCooldownMinutes = settings.FailureCooldownMinutes,
                HealthCheckTimeoutSeconds = settings.HealthCheckTimeoutSeconds
            };

            _services.Logger.Log($"Manual login context: ac_id={effective.AcId}, portal={effective.PortalHost}");
            var result = await _services.PortalLoginClient.LoginAsync(effective, credential, CancellationToken.None, context.IsWireless);
            _services.Logger.Log($"手动登录 => success={result.Success}, finalUrl={result.FinalUrl}, message={result.Message}");
            if (result.Trace.Count > 0)
            {
                _services.Logger.Log($"手动登录 trace => {string.Join(" | ", result.Trace)}");
            }

            SetStatus(result.Success ? $"登录成功：{result.Message}" : $"登录失败：{result.Message}");
            RefreshUi();
        }, disableUi: false);
    }

    private async void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(async () =>
        {
            await SaveFromUiAsync(requireCredential: false);

            if (_services.MonitorService.IsRunning)
            {
                await _services.MonitorService.StopAsync();
                _services.Logger.Log("手动注销前已暂停后台监控。");
            }

            if (MonitorEnabledCheckBox.IsChecked == true)
            {
                _isLoadingUiModel = true;
                try
                {
                    MonitorEnabledCheckBox.IsChecked = false;
                }
                finally
                {
                    _isLoadingUiModel = false;
                }

                var updated = _services.SettingsStore.Load();
                updated.EnableBackgroundMonitor = false;
                _services.SettingsStore.Save(updated);
                _services.Logger.Log("手动注销后已自动取消后台监控勾选。");
            }

            var settings = _services.SettingsStore.Load();
            var result = await _services.PortalLoginClient.LogoutAsync(settings, CancellationToken.None);
            _services.Logger.Log($"手动注销 => success={result.Success}, finalUrl={result.FinalUrl}, message={result.Message}");
            if (result.Trace.Count > 0)
            {
                _services.Logger.Log($"手动注销 trace => {string.Join(" | ", result.Trace)}");
            }

            SetStatus(result.Success
                ? $"注销成功：{result.Message}（后台监控已关闭）"
                : $"注销失败：{result.Message}（后台监控已关闭）");
            RefreshUi();
        }, disableUi: false);
    }

    private async void MonitorEnabledCheckBox_CheckedChanged(object sender, RoutedEventArgs e)
    {
        if (_isLoadingUiModel)
        {
            return;
        }

        await ExecuteGuardedAsync(async () =>
        {
            await ApplyMonitorSwitchAsync();
            RefreshUi();
        }, disableUi: false);
    }

    private async void StartupCheckBox_CheckedChanged(object sender, RoutedEventArgs e)
    {
        if (_isLoadingUiModel)
        {
            return;
        }

        await ExecuteGuardedAsync(() =>
        {
            var enabled = StartupCheckBox.IsChecked == true;
            _services.StartupManager.SetEnabled(enabled);
            _services.Logger.Log(enabled ? "开机自启动已开启。" : "开机自启动已关闭。");
            RefreshUi();
            return Task.CompletedTask;
        }, disableUi: false);
    }

    private void OpenLogsButton_Click(object sender, RoutedEventArgs e)
    {
        var path = _services.Logger.OpenLogsDirectory();
        Process.Start(new ProcessStartInfo("explorer.exe", path) { UseShellExecute = true });
    }

    private async void ClearLogsButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(() =>
        {
            var removed = _services.Logger.ClearAllLogs();
            _lastLogSnapshot = string.Empty;
            LogTextBox.Clear();
            _services.Logger.Log($"日志已手动清空，删除文件数: {removed}.");
            SetStatus("日志已清空。");
            RefreshUi();
            return Task.CompletedTask;
        }, disableUi: false);
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        HideToTray();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            HideToTray();
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_allowExit)
        {
            e.Cancel = true;
            HideToTray();
            return;
        }

        _refreshTimer.Stop();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }

    private void HideToTray()
    {
        if (!_notifyIcon.Visible)
        {
            _notifyIcon.Visible = true;
        }

        Hide();
        ShowInTaskbar = false;
        _notifyIcon.BalloonTipTitle = "东北大学校园网自动登录";
        _notifyIcon.BalloonTipText = "程序已最小化到系统托盘，如未显示请点击右下角 ^。";
        _notifyIcon.ShowBalloonTip(2000);
    }

    private void ShowFromTray()
    {
        ShowInTaskbar = true;
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void RefreshUi()
    {
        var settings = _services.SettingsStore.Load();
        if (settings.EnableBackgroundMonitor &&
            !_services.MonitorService.IsRunning &&
            !_services.MonitorService.IsRunningInAnotherProcess)
        {
            _ = EnsureMonitorRunningAsync();
        }

        var startup = _services.StartupManager.IsEnabled() ? "开机自启：已开启" : "开机自启：未开启";
        var monitor = !settings.EnableBackgroundMonitor
            ? "后台监控：已禁用"
            : _services.MonitorService.IsRunning
                ? "后台监控：运行中"
                : _services.MonitorService.IsRunningInAnotherProcess
                    ? "后台监控：已由后台实例运行"
                    : "后台监控：已启用（等待启动）";
        SetStatus($"{startup} | {monitor}");

        var logText = _services.Logger.ReadTail();
        if (!string.Equals(logText, _lastLogSnapshot, StringComparison.Ordinal))
        {
            _lastLogSnapshot = logText;
            LogTextBox.Text = logText;
            LogTextBox.ScrollToEnd();
        }
    }

    private void SetStatus(string message)
    {
        StatusTextBlock.Text = message;
    }

    private Forms.NotifyIcon CreateNotifyIcon()
    {
        var trayIcon = ResolveTrayIcon();
        var icon = new Forms.NotifyIcon
        {
            Text = "东北大学校园网自动登录",
            Icon = trayIcon,
            Visible = true
        };

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("显示主界面", null, (_, _) => ShowFromTray());
        menu.Items.Add("退出程序", null, async (_, _) =>
        {
            _allowExit = true;
            await _services.MonitorService.StopAsync();
            Close();
            System.Windows.Application.Current.Shutdown();
        });
        icon.ContextMenuStrip = menu;

        icon.DoubleClick += (_, _) => ShowFromTray();
        icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
            {
                ShowFromTray();
            }
        };

        return icon;
    }

    private async Task ExecuteGuardedAsync(Func<Task> action, bool disableUi = true)
    {
        try
        {
            if (disableUi)
            {
                ToggleUi(false);
            }

            await action();
        }
        catch (Exception ex)
        {
            _services.Logger.Log($"UI action failed: {ex.Message}");
            Forms.MessageBox.Show(ex.Message, "操作失败", Forms.MessageBoxButtons.OK, Forms.MessageBoxIcon.Error);
        }
        finally
        {
            if (disableUi)
            {
                ToggleUi(true);
            }
        }
    }

    private Drawing.Icon ResolveTrayIcon()
    {
        try
        {
            var processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) && File.Exists(processPath))
            {
                var extracted = Drawing.Icon.ExtractAssociatedIcon(processPath);
                if (extracted is not null)
                {
                    return (Drawing.Icon)extracted.Clone();
                }
            }
        }
        catch
        {
        }

        return Drawing.SystemIcons.Information;
    }

    private void ToggleUi(bool enabled)
    {
        SaveButton.IsEnabled = enabled;
        LoginButton.IsEnabled = enabled;
        LogoutButton.IsEnabled = enabled;
        OpenLogsButton.IsEnabled = enabled;
        ClearLogsButton.IsEnabled = enabled;
        MinimizeButton.IsEnabled = enabled;
        MonitorEnabledCheckBox.IsEnabled = enabled;
        StartupCheckBox.IsEnabled = enabled;
    }

    private async Task EnsureMonitorRunningAsync()
    {
        if (Interlocked.CompareExchange(ref _monitorEnsureInProgress, 1, 0) != 0)
        {
            return;
        }

        try
        {
            var startResult = await _services.MonitorService.StartAsync();
            if (startResult == MonitorService.StartResult.Started)
            {
                _services.Logger.Log("后台监控自动补启动成功。");
            }
        }
        catch (Exception ex)
        {
            _services.Logger.Log($"后台监控自动补启动失败: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _monitorEnsureInProgress, 0);
        }
    }
}
