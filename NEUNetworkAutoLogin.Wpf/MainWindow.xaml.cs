using System.ComponentModel;
using System.Diagnostics;
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
        var settings = _services.SettingsStore.Load();
        var credential = _services.CredentialStore.Load();

        UsernameBox.Text = credential.Username;
        PasswordBox.Password = credential.Password;
        PortalHostBox.Text = settings.PortalHost;
        ServiceBaseUrlBox.Text = settings.ServiceBaseUrl;
        AcIdBox.Text = settings.AcId.ToString();
        StartupCheckBox.IsChecked = _services.StartupManager.IsEnabled();
    }

    private AppSettings CollectSettingsFromUi(bool requireCredential)
    {
        if (!int.TryParse(AcIdBox.Text.Trim(), out var acId) || acId <= 0)
        {
            throw new InvalidOperationException("AC ID 必须是大于 0 的整数。");
        }

        var portalHost = PortalHostBox.Text.Trim();
        var serviceBaseUrl = ServiceBaseUrlBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(portalHost) || string.IsNullOrWhiteSpace(serviceBaseUrl))
        {
            throw new InvalidOperationException("Portal Host 与 Service Base URL 不能为空。");
        }

        if (requireCredential &&
            (string.IsNullOrWhiteSpace(UsernameBox.Text) || string.IsNullOrWhiteSpace(PasswordBox.Password)))
        {
            throw new InvalidOperationException("账号和密码不能为空。");
        }

        var current = _services.SettingsStore.Load();
        current.AcId = acId;
        current.PortalHost = portalHost;
        current.ServiceBaseUrl = serviceBaseUrl;
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

        var hasCredential = !string.IsNullOrWhiteSpace(UsernameBox.Text) && !string.IsNullOrWhiteSpace(PasswordBox.Password);
        if (requireCredential || hasCredential)
        {
            var credential = CollectCredentialFromUi();
            _services.CredentialStore.Save(credential);
        }

        _services.Logger.Log("配置已保存。");
        await Task.CompletedTask;
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
            var result = await _services.PortalLoginClient.LoginAsync(settings, credential, CancellationToken.None);
            _services.Logger.Log($"手动登录 => success={result.Success}, finalUrl={result.FinalUrl}, message={result.Message}");
            if (result.Trace.Count > 0)
            {
                _services.Logger.Log($"手动登录 trace => {string.Join(" | ", result.Trace)}");
            }

            SetStatus(result.Success
                ? $"登录成功：{result.Message}"
                : $"登录失败：{result.Message}");
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

            var settings = _services.SettingsStore.Load();
            var result = await _services.PortalLoginClient.LogoutAsync(settings, CancellationToken.None);
            _services.Logger.Log($"手动注销 => success={result.Success}, finalUrl={result.FinalUrl}, message={result.Message}");
            if (result.Trace.Count > 0)
            {
                _services.Logger.Log($"手动注销 trace => {string.Join(" | ", result.Trace)}");
            }

            SetStatus(result.Success
                ? $"注销成功：{result.Message}（后台监控已暂停）"
                : $"注销失败：{result.Message}（后台监控已暂停）");
            RefreshUi();
        }, disableUi: false);
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(async () =>
        {
            await SaveFromUiAsync(requireCredential: false);
            await _services.MonitorService.StartAsync();
            SetStatus("监控已启动。");
            RefreshUi();
        });
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteGuardedAsync(async () =>
        {
            await _services.MonitorService.StopAsync();
            SetStatus("监控已停止。");
            RefreshUi();
        });
    }

    private void OpenLogsButton_Click(object sender, RoutedEventArgs e)
    {
        var path = _services.Logger.OpenLogsDirectory();
        Process.Start(new ProcessStartInfo("explorer.exe", path) { UseShellExecute = true });
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
        var startup = _services.StartupManager.IsEnabled() ? "开机自启：已开启" : "开机自启：未开启";
        var monitor = _services.MonitorService.IsRunning ? "后台监控：运行中" : "后台监控：未运行";
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
        StartButton.IsEnabled = enabled;
        StopButton.IsEnabled = enabled;
        OpenLogsButton.IsEnabled = enabled;
        MinimizeButton.IsEnabled = enabled;
    }
}
