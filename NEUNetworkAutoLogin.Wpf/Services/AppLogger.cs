using System.Text;

namespace NEUNetworkAutoLogin.Services;

public sealed class AppLogger
{
    private readonly AppPaths _paths;
    private readonly object _sync = new();

    public AppLogger(AppPaths paths)
    {
        _paths = paths;
        Directory.CreateDirectory(_paths.LogsDirectory);
    }

    public void Log(string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
        lock (_sync)
        {
            File.AppendAllText(GetDailyLogPath(), line, Encoding.UTF8);
        }
    }

    public string ReadTail(int maxLines = 300)
    {
        var path = GetLatestLogPath();
        if (path is null)
        {
            return "No logs generated yet.";
        }

        try
        {
            var lines = File.ReadLines(path).TakeLast(maxLines);
            return string.Join(Environment.NewLine, lines);
        }
        catch (Exception ex)
        {
            return $"Failed to read logs: {ex.Message}";
        }
    }

    public string OpenLogsDirectory()
    {
        Directory.CreateDirectory(_paths.LogsDirectory);
        return _paths.LogsDirectory;
    }

    public void CleanupOldLogs(int keepDays = 7)
    {
        if (keepDays < 1)
        {
            keepDays = 1;
        }

        var cutoff = DateTime.Now.Date.AddDays(-keepDays);
        lock (_sync)
        {
            if (!Directory.Exists(_paths.LogsDirectory))
            {
                return;
            }

            foreach (var file in Directory.EnumerateFiles(_paths.LogsDirectory, "autologin-*.log"))
            {
                try
                {
                    var lastWrite = File.GetLastWriteTime(file);
                    if (lastWrite < cutoff)
                    {
                        File.Delete(file);
                    }
                }
                catch
                {
                    // best effort cleanup on exit
                }
            }
        }
    }

    public int ClearAllLogs()
    {
        lock (_sync)
        {
            if (!Directory.Exists(_paths.LogsDirectory))
            {
                return 0;
            }

            var removed = 0;
            foreach (var file in Directory.EnumerateFiles(_paths.LogsDirectory, "autologin-*.log"))
            {
                try
                {
                    File.Delete(file);
                    removed++;
                }
                catch
                {
                    // ignore single file deletion failures and continue.
                }
            }

            return removed;
        }
    }

    private string GetDailyLogPath()
    {
        return Path.Combine(_paths.LogsDirectory, $"autologin-{DateTime.Now:yyyy-MM-dd}.log");
    }

    private string? GetLatestLogPath()
    {
        Directory.CreateDirectory(_paths.LogsDirectory);
        return Directory.EnumerateFiles(_paths.LogsDirectory, "autologin-*.log")
            .OrderByDescending(File.GetLastWriteTime)
            .FirstOrDefault();
    }
}
