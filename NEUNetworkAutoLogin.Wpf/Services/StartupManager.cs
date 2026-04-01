namespace NEUNetworkAutoLogin.Services;

public sealed class StartupManager
{
    private readonly AppPaths _paths;

    public StartupManager(AppPaths paths)
    {
        _paths = paths;
    }

    public bool IsEnabled()
    {
        return File.Exists(_paths.StartupShortcutPath);
    }

    public void SetEnabled(bool enabled)
    {
        if (!enabled)
        {
            if (File.Exists(_paths.StartupShortcutPath))
            {
                File.Delete(_paths.StartupShortcutPath);
            }
            return;
        }

        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath))
        {
            throw new InvalidOperationException("Cannot resolve current executable path.");
        }

        var workingDirectory = Path.GetDirectoryName(exePath) ?? _paths.BaseDirectory;
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell COM is unavailable.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(_paths.StartupShortcutPath);
        shortcut.TargetPath = exePath;
        shortcut.Arguments = "--background";
        shortcut.WorkingDirectory = workingDirectory;
        shortcut.WindowStyle = 7;
        shortcut.Description = "NEU Network Auto Login";
        shortcut.Save();
    }
}
