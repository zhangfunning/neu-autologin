using System.Threading;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class MonitorService
{
    private const string MutexName = @"Local\NEUNetworkAutoLogin_Monitor";

    private readonly AppLogger _logger;
    private readonly JsonSettingsStore _settingsStore;
    private readonly CredentialStore _credentialStore;
    private readonly NetworkProbeService _probeService;
    private readonly PortalLoginClient _portalLoginClient;
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);

    private Mutex? _mutex;
    private CancellationTokenSource? _runCts;
    private Task? _runTask;

    public MonitorService(
        AppLogger logger,
        JsonSettingsStore settingsStore,
        CredentialStore credentialStore,
        NetworkProbeService probeService,
        PortalLoginClient portalLoginClient)
    {
        _logger = logger;
        _settingsStore = settingsStore;
        _credentialStore = credentialStore;
        _probeService = probeService;
        _portalLoginClient = portalLoginClient;
    }

    public bool IsRunning => _runTask is { IsCompleted: false };

    public bool IsRunningInAnotherProcess
    {
        get
        {
            CleanupCompletedRunBestEffort();
            return !IsRunning && IsMutexHeldByAnotherProcess();
        }
    }

    public enum StartResult
    {
        Started,
        AlreadyRunningLocally,
        AlreadyRunningInAnotherProcess,
        DisabledBySettings
    }

    public async Task<StartResult> StartAsync(CancellationToken externalToken = default)
    {
        await _lifecycleLock.WaitAsync(externalToken);
        try
        {
            CleanupCompletedRunUnsafe();

            if (IsRunning)
            {
                return StartResult.AlreadyRunningLocally;
            }

            var settings = _settingsStore.Load();
            if (!settings.EnableBackgroundMonitor)
            {
                _logger.Log("Monitor start skipped because background monitor is disabled in settings.");
                return StartResult.DisabledBySettings;
            }

            if (!TryAcquireMutex())
            {
                return StartResult.AlreadyRunningInAnotherProcess;
            }

            _runCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
            _runTask = Task.Run(() => RunLoopAsync(_runCts.Token), CancellationToken.None);
            return StartResult.Started;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task StopAsync()
    {
        await _lifecycleLock.WaitAsync();
        try
        {
            CleanupCompletedRunUnsafe();

            if (_runCts is null || _runTask is null)
            {
                ReleaseMutex();
                return;
            }

            _runCts.Cancel();
            try
            {
                await _runTask;
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                _runCts.Dispose();
                _runCts = null;
                _runTask = null;
                ReleaseMutex();
            }
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private void CleanupCompletedRunBestEffort()
    {
        if (!_lifecycleLock.Wait(0))
        {
            return;
        }

        try
        {
            CleanupCompletedRunUnsafe();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private void CleanupCompletedRunUnsafe()
    {
        if (_runTask is { IsCompleted: true })
        {
            try
            {
                _runTask.GetAwaiter().GetResult();
            }
            catch
            {
                // monitor loop exception has been logged already.
            }

            _runTask = null;
            _runCts?.Dispose();
            _runCts = null;
            ReleaseMutex();
        }
    }

    private bool IsMutexHeldByAnotherProcess()
    {
        using var probeMutex = new Mutex(false, MutexName);
        try
        {
            var acquired = probeMutex.WaitOne(0, false);
            if (acquired)
            {
                probeMutex.ReleaseMutex();
                return false;
            }

            return true;
        }
        catch (AbandonedMutexException)
        {
            try
            {
                probeMutex.ReleaseMutex();
            }
            catch
            {
            }

            return false;
        }
    }

    private bool TryAcquireMutex()
    {
        var mutex = new Mutex(false, MutexName);
        try
        {
            var acquired = mutex.WaitOne(0, false);
            if (!acquired)
            {
                mutex.Dispose();
                return false;
            }

            _mutex = mutex;
            return true;
        }
        catch (AbandonedMutexException)
        {
            _mutex = mutex;
            return true;
        }
    }

    private void ReleaseMutex()
    {
        if (_mutex is null)
        {
            return;
        }

        try
        {
            _mutex.ReleaseMutex();
        }
        catch
        {
        }
        finally
        {
            _mutex.Dispose();
            _mutex = null;
        }
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        _logger.Log("Autologin monitor started.");

        try
        {
            var settings = _settingsStore.Load();
            if (!settings.EnableBackgroundMonitor)
            {
                _logger.Log("Background monitor is disabled. Monitor loop exited.");
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(settings.InitialDelaySeconds), cancellationToken);

            var lastHealthState = (bool?)null;
            var nextLoginAllowedAt = DateTimeOffset.Now;
            var cooldownNoticeLogged = false;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    settings = _settingsStore.Load();
                    if (!settings.EnableBackgroundMonitor)
                    {
                        _logger.Log("Background monitor option turned off. Monitor loop stopped.");
                        break;
                    }

                    var healthy = await _probeService.IsHealthyAsync(settings, cancellationToken);

                    if (lastHealthState != healthy)
                    {
                        _logger.Log(healthy
                            ? "Network health check: online."
                            : "Network health check: offline or captive portal detected.");
                        lastHealthState = healthy;
                    }

                    if (!healthy)
                    {
                        if (DateTimeOffset.Now >= nextLoginAllowedAt)
                        {
                            cooldownNoticeLogged = false;
                            var portalContext = await _probeService.ResolvePortalContextAsync(settings, cancellationToken);
                            _logger.Log($"Selected login context: ac_id={portalContext.AcId}, portal={portalContext.PortalHost}");

                            var credential = _credentialStore.Load();
                            if (string.IsNullOrWhiteSpace(credential.Username) || string.IsNullOrWhiteSpace(credential.Password))
                            {
                                _logger.Log("Credential is empty. Skip login.");
                            }
                            else
                            {
                                var success = await TryLoginBurstAsync(settings, portalContext, credential, cancellationToken);
                                if (success)
                                {
                                    lastHealthState = null;
                                }
                                else
                                {
                                    nextLoginAllowedAt = DateTimeOffset.Now.AddMinutes(settings.FailureCooldownMinutes);
                                    _logger.Log($"Entering cooldown until {nextLoginAllowedAt:yyyy-MM-dd HH:mm:ss}.");
                                    cooldownNoticeLogged = true;
                                }
                            }
                        }
                        else if (!cooldownNoticeLogged)
                        {
                            _logger.Log($"Cooldown active; skipping login until {nextLoginAllowedAt:yyyy-MM-dd HH:mm:ss}.");
                            cooldownNoticeLogged = true;
                        }
                    }
                    else
                    {
                        cooldownNoticeLogged = false;
                    }

                    await Task.Delay(TimeSpan.FromSeconds(settings.MonitorIntervalSeconds), cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Log($"Monitor loop error: {ex.Message}");
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            _logger.Log("Autologin monitor stopped.");
        }
    }

    private async Task<bool> TryLoginBurstAsync(
        AppSettings settings,
        PortalContext context,
        CredentialModel credential,
        CancellationToken cancellationToken)
    {
        var effective = new AppSettings
        {
            AcId = context.AcId > 0 ? context.AcId : settings.AcId,
            PortalHost = string.IsNullOrWhiteSpace(context.PortalHost) ? settings.PortalHost : context.PortalHost,
            ServiceBaseUrl = settings.ServiceBaseUrl,
            InitialDelaySeconds = settings.InitialDelaySeconds,
            RetryDelaySeconds = settings.RetryDelaySeconds,
            MaxAttempts = settings.MaxAttempts,
            MonitorIntervalSeconds = settings.MonitorIntervalSeconds,
            FailureCooldownMinutes = settings.FailureCooldownMinutes,
            HealthCheckTimeoutSeconds = settings.HealthCheckTimeoutSeconds
        };

        for (var attempt = 1; attempt <= settings.MaxAttempts; attempt++)
        {
            _logger.Log($"Login attempt {attempt}/{settings.MaxAttempts} (ac_id={effective.AcId}).");
            var result = await _portalLoginClient.LoginAsync(effective, credential, cancellationToken, context.IsWireless);
            _logger.Log($"login => success={result.Success}, finalUrl={result.FinalUrl}, message={result.Message}");
            if (result.Trace.Count > 0)
            {
                _logger.Log($"trace => {string.Join(" | ", result.Trace)}");
            }

            if (result.Success)
            {
                _logger.Log("Autologin succeeded.");
                return true;
            }

            if (attempt < settings.MaxAttempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(settings.RetryDelaySeconds), cancellationToken);
            }
        }

        _logger.Log("Autologin failed after all retries.");
        return false;
    }
}
