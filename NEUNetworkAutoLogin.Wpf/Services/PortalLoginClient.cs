using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class PortalLoginClient
{
    private const string HelperResourceName = "NEUNetworkAutoLogin.Resources.portal-sso-login.js";
    private static readonly Regex WhiteSpaceRegex = new(@"\s+", RegexOptions.Compiled);
    private static readonly object HelperWriteLock = new();
    private static readonly object NodeDepsLock = new();

    private readonly AppPaths _paths;

    public PortalLoginClient(AppPaths paths)
    {
        _paths = paths;
    }

    public Task<PortalLoginResult> LoginAsync(
        AppSettings settings,
        CredentialModel credential,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(credential.Username) || string.IsNullOrWhiteSpace(credential.Password))
        {
            return Task.FromResult(new PortalLoginResult
            {
                Success = false,
                Message = "账号或密码为空。"
            });
        }

        return InvokeBrowserPortalAsync(settings, credential, "login", cancellationToken);
    }

    public Task<PortalLoginResult> LogoutAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        return InvokeBrowserPortalAsync(settings, credential: null, "logout", cancellationToken);
    }

    private async Task<PortalLoginResult> InvokeBrowserPortalAsync(
        AppSettings settings,
        CredentialModel? credential,
        string mode,
        CancellationToken cancellationToken)
    {
        var normalizedMode = string.Equals(mode, "logout", StringComparison.OrdinalIgnoreCase)
            ? "logout"
            : "login";

        var trace = new List<string>();
        var helperPath = ResolvePortalHelperPath();
        if (helperPath is null)
        {
            return new PortalLoginResult
            {
                Success = false,
                Message = "未找到浏览器认证脚本（bin/portal-sso-login.js）。"
            };
        }

        if (!EnsurePlaywrightCoreAvailable(helperPath, trace))
        {
            return new PortalLoginResult
            {
                Success = false,
                Message = "缺少运行依赖 playwright-core，且自动修复失败。",
                Trace = trace
            };
        }

        var payload = new
        {
            Mode = normalizedMode,
            Username = credential?.Username?.Trim() ?? string.Empty,
            Password = credential?.Password ?? string.Empty,
            AcId = settings.AcId,
            PortalHost = NormalizePortalHost(settings.PortalHost),
            ServiceBaseUrl = BuildServiceUrl(settings)
        };
        var inputJson = JsonSerializer.Serialize(payload);

        var startInfo = new ProcessStartInfo
        {
            FileName = "node",
            Arguments = $"--no-warnings \"{helperPath}\"",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        startInfo.Environment["FORCE_COLOR"] = "0";

        Process? process = null;
        try
        {
            process = new Process { StartInfo = startInfo };
            if (!process.Start())
            {
                return new PortalLoginResult
                {
                    Success = false,
                    Message = "无法启动 Node 进程。"
                };
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(normalizedMode == "logout" ? TimeSpan.FromSeconds(180) : TimeSpan.FromSeconds(210));
            var token = timeoutCts.Token;

            await process.StandardInput.WriteAsync(inputJson.AsMemory(), token);
            await process.StandardInput.FlushAsync();
            process.StandardInput.Close();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(token);
            var stderrTask = process.StandardError.ReadToEndAsync(token);
            await process.WaitForExitAsync(token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            trace.Add($"browser-{normalizedMode} exit={process.ExitCode}");
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                trace.Add($"browser-{normalizedMode} stderr={ToSingleLine(stderr)}");
            }

            if (!TryParseJsonFromText(stdout, out var doc, out var parseError))
            {
                if (!string.IsNullOrWhiteSpace(parseError))
                {
                    trace.Add($"browser-{normalizedMode} parse-error={ToSingleLine(parseError)}");
                }

                var snippet = ToSingleLine(stdout);
                if (!string.IsNullOrWhiteSpace(snippet))
                {
                    trace.Add($"browser-{normalizedMode} stdout={snippet[..Math.Min(400, snippet.Length)]}");
                }

                return new PortalLoginResult
                {
                    Success = false,
                    Message = normalizedMode == "logout" ? "注销返回结果无法解析。" : "登录返回结果无法解析。",
                    Trace = trace
                };
            }

            if (doc is null)
            {
                return new PortalLoginResult
                {
                    Success = false,
                    Message = normalizedMode == "logout" ? "注销结果为空。" : "登录结果为空。",
                    Trace = trace
                };
            }

            using (doc)
            {
                var root = doc.RootElement;
                var success = GetBoolean(root, "ok") || GetBoolean(root, "successPage");
                var finalUrl = GetString(root, "finalUrl");

                var message = GetString(root, "errorMessage");
                if (string.IsNullOrWhiteSpace(message))
                {
                    message = GetString(root, "message");
                }
                if (string.IsNullOrWhiteSpace(message))
                {
                    message = success
                        ? (normalizedMode == "logout" ? "已注销校园网登录。" : "登录成功。")
                        : (normalizedMode == "logout" ? "注销失败。" : "登录失败。");
                }

                var combinedTrace = new List<string>(trace);
                if (root.TryGetProperty("trace", out var traceElement) && traceElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var line in traceElement.EnumerateArray())
                    {
                        var item = line.GetString();
                        if (!string.IsNullOrWhiteSpace(item))
                        {
                            combinedTrace.Add($"browser {item}");
                        }
                    }
                }

                return new PortalLoginResult
                {
                    Success = success,
                    Message = ToSingleLine(message),
                    FinalUrl = finalUrl ?? string.Empty,
                    Trace = combinedTrace
                };
            }
        }
        catch (OperationCanceledException)
        {
            TryKillProcessTree(process);
            return new PortalLoginResult
            {
                Success = false,
                Message = normalizedMode == "logout" ? "注销超时，请稍后重试。" : "登录超时，请稍后重试。",
                Trace = trace
            };
        }
        catch (Exception ex)
        {
            trace.Add($"browser-{normalizedMode} error={ToSingleLine(ex.Message)}");
            return new PortalLoginResult
            {
                Success = false,
                Message = (normalizedMode == "logout" ? "浏览器注销失败：" : "浏览器登录失败：") + ToSingleLine(ex.Message),
                Trace = trace
            };
        }
        finally
        {
            process?.Dispose();
        }
    }

    private string? ResolvePortalHelperPath()
    {
        var baseDir = AppContext.BaseDirectory;
        var processDir = Path.GetDirectoryName(Environment.ProcessPath ?? string.Empty) ?? string.Empty;
        var candidates = new[]
        {
            Path.Combine(baseDir, "bin", "portal-sso-login.js"),
            Path.Combine(baseDir, "..", "bin", "portal-sso-login.js"),
            Path.Combine(baseDir, "..", "..", "bin", "portal-sso-login.js"),
            Path.Combine(processDir, "bin", "portal-sso-login.js"),
            _paths.PortalHelperScriptPath
        };

        foreach (var candidate in candidates)
        {
            var fullPath = Path.GetFullPath(candidate);
            if (File.Exists(fullPath))
            {
                return fullPath;
            }
        }

        if (TryExtractEmbeddedHelper(_paths.PortalHelperScriptPath))
        {
            return _paths.PortalHelperScriptPath;
        }

        return null;
    }

    private bool EnsurePlaywrightCoreAvailable(string helperPath, List<string> trace)
    {
        try
        {
            var helperDir = Path.GetDirectoryName(helperPath);
            if (string.IsNullOrWhiteSpace(helperDir))
            {
                trace.Add("deps helper-dir-empty");
                return false;
            }

            lock (NodeDepsLock)
            {
                if (HasPlaywrightCore(helperDir))
                {
                    return true;
                }

                var targetNodeModules = Path.Combine(helperDir, "node_modules");
                foreach (var source in GetNodeModuleSourceCandidates())
                {
                    if (!Directory.Exists(source))
                    {
                        continue;
                    }

                    if (!Directory.Exists(Path.Combine(source, "playwright-core")))
                    {
                        continue;
                    }

                    try
                    {
                        CopyDirectory(source, targetNodeModules);
                        if (HasPlaywrightCore(helperDir))
                        {
                            trace.Add($"deps copied-from={source}");
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        trace.Add($"deps copy-failed from={source} err={ToSingleLine(ex.Message)}");
                    }
                }

                if (TryInstallPlaywrightCore(helperDir, trace))
                {
                    return true;
                }

                return false;
            }
        }
        catch (Exception ex)
        {
            trace.Add($"deps ensure-error={ToSingleLine(ex.Message)}");
            return false;
        }
    }

    private IEnumerable<string> GetNodeModuleSourceCandidates()
    {
        var baseDir = AppContext.BaseDirectory;
        var processDir = Path.GetDirectoryName(Environment.ProcessPath ?? string.Empty) ?? string.Empty;
        var candidates = new[]
        {
            Path.Combine(baseDir, "bin", "node_modules"),
            Path.Combine(baseDir, "..", "bin", "node_modules"),
            Path.Combine(baseDir, "..", "..", "bin", "node_modules"),
            Path.Combine(processDir, "bin", "node_modules"),
            Path.Combine(_paths.HelpersDirectory, "node_modules")
        };

        return candidates.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static bool HasPlaywrightCore(string helperDir)
    {
        var packageJsonPath = Path.Combine(helperDir, "node_modules", "playwright-core", "package.json");
        return File.Exists(packageJsonPath);
    }

    private static bool TryInstallPlaywrightCore(string helperDir, List<string> trace)
    {
        if (!TryResolveNpmCommand(out var npmFileName, out var npmArgumentsPrefix))
        {
            trace.Add("deps npm-not-found");
            return false;
        }

        Directory.CreateDirectory(helperDir);
        var startInfo = new ProcessStartInfo
        {
            FileName = npmFileName,
            Arguments = $"{npmArgumentsPrefix} install playwright-core --no-save --silent",
            WorkingDirectory = helperDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                trace.Add("deps npm-start-failed");
                return false;
            }

            process.WaitForExit(120000);
            if (!process.HasExited)
            {
                try { process.Kill(true); } catch { }
                trace.Add("deps npm-timeout");
                return false;
            }

            if (process.ExitCode != 0)
            {
                var err = process.StandardError.ReadToEnd();
                trace.Add($"deps npm-exit={process.ExitCode} err={ToSingleLine(err)}");
                return false;
            }

            var ok = HasPlaywrightCore(helperDir);
            trace.Add(ok ? "deps npm-install-ok" : "deps npm-install-missing");
            return ok;
        }
        catch (Exception ex)
        {
            trace.Add($"deps npm-error={ToSingleLine(ex.Message)}");
            return false;
        }
    }

    private static bool TryResolveNpmCommand(out string fileName, out string argumentsPrefix)
    {
        fileName = string.Empty;
        argumentsPrefix = string.Empty;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var candidates = new[]
        {
            Path.Combine(programFiles, "nodejs", "npm.cmd"),
            Path.Combine(programFilesX86, "nodejs", "npm.cmd"),
            Path.Combine(appData, "npm", "npm.cmd")
        };

        foreach (var candidate in candidates)
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            if (TryRunVersionCommand(candidate, string.Empty))
            {
                fileName = candidate;
                argumentsPrefix = string.Empty;
                return true;
            }
        }

        // Fallback: let cmd resolve npm from PATH (works for npm.cmd alias).
        if (TryRunVersionCommand("cmd.exe", "/d /c npm"))
        {
            fileName = "cmd.exe";
            argumentsPrefix = "/d /c npm";
            return true;
        }

        return false;
    }

    private static bool TryRunVersionCommand(string fileName, string argumentsPrefix)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = string.IsNullOrWhiteSpace(argumentsPrefix)
                    ? "--version"
                    : $"{argumentsPrefix} --version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                return false;
            }

            process.WaitForExit(8000);
            return process.HasExited && process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);

        foreach (var file in Directory.GetFiles(sourceDir))
        {
            var targetFile = Path.Combine(targetDir, Path.GetFileName(file));
            File.Copy(file, targetFile, overwrite: true);
        }

        foreach (var directory in Directory.GetDirectories(sourceDir))
        {
            var targetSubDir = Path.Combine(targetDir, Path.GetFileName(directory));
            CopyDirectory(directory, targetSubDir);
        }
    }

    private static void TryKillProcessTree(Process? process)
    {
        try
        {
            if (process is { HasExited: false })
            {
                process.Kill(true);
            }
        }
        catch
        {
        }
    }

    private static string BuildServiceUrl(AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.ServiceBaseUrl))
        {
            return $"https://ipgw.neu.edu.cn/srun_portal_sso?ac_id={settings.AcId}";
        }

        var serviceBaseUrl = settings.ServiceBaseUrl.Trim();
        if (serviceBaseUrl.Contains("ac_id=", StringComparison.OrdinalIgnoreCase))
        {
            return serviceBaseUrl;
        }

        var separator = serviceBaseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{serviceBaseUrl}{separator}ac_id={settings.AcId}";
    }

    private static string NormalizePortalHost(string input)
    {
        var host = string.IsNullOrWhiteSpace(input) ? "https://ipgw.neu.edu.cn/" : input.Trim();
        if (!host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            host = $"https://{host}";
        }

        if (host.StartsWith("http://ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase))
        {
            host = "https://" + host["http://".Length..];
        }

        if (!host.EndsWith("/", StringComparison.Ordinal))
        {
            host += "/";
        }

        return host;
    }

    private static bool TryExtractEmbeddedHelper(string targetPath)
    {
        try
        {
            lock (HelperWriteLock)
            {
                if (File.Exists(targetPath))
                {
                    return true;
                }

                var assembly = typeof(PortalLoginClient).Assembly;
                var stream = assembly.GetManifestResourceStream(HelperResourceName);
                if (stream is null)
                {
                    var fallbackName = assembly.GetManifestResourceNames()
                        .FirstOrDefault(name => name.EndsWith("portal-sso-login.js", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrWhiteSpace(fallbackName))
                    {
                        stream = assembly.GetManifestResourceStream(fallbackName);
                    }
                }

                if (stream is null)
                {
                    return false;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                var tmpPath = targetPath + ".tmp";
                using (var fileStream = File.Create(tmpPath))
                {
                    stream.CopyTo(fileStream);
                }
                stream.Dispose();

                File.Move(tmpPath, targetPath, overwrite: true);
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool GetBoolean(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            JsonValueKind.Number => value.TryGetInt32(out var n) && n != 0,
            _ => false
        };
    }

    private static string GetString(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value))
        {
            return string.Empty;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => string.Empty
        };
    }

    private static bool TryParseJsonFromText(string text, out JsonDocument? document, out string parseError)
    {
        document = null;
        parseError = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
        {
            parseError = "empty output";
            return false;
        }

        var trimmed = text.Trim();
        if (TryParseJson(trimmed, out document, out parseError))
        {
            return true;
        }

        var lines = trimmed
            .Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.StartsWith("{", StringComparison.Ordinal) && line.EndsWith("}", StringComparison.Ordinal))
            .ToList();

        for (var i = lines.Count - 1; i >= 0; i--)
        {
            if (TryParseJson(lines[i], out document, out parseError))
            {
                return true;
            }
        }

        var objects = ExtractJsonObjects(trimmed);
        for (var i = objects.Count - 1; i >= 0; i--)
        {
            if (TryParseJson(objects[i], out document, out parseError))
            {
                return true;
            }
        }

        return false;
    }

    private static List<string> ExtractJsonObjects(string text)
    {
        var result = new List<string>();
        var start = -1;
        var depth = 0;
        var inString = false;
        var escaping = false;

        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (inString)
            {
                if (escaping)
                {
                    escaping = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaping = true;
                    continue;
                }

                if (ch == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == '"')
            {
                inString = true;
                continue;
            }

            if (ch == '{')
            {
                if (depth == 0)
                {
                    start = i;
                }
                depth++;
                continue;
            }

            if (ch != '}')
            {
                continue;
            }

            if (depth <= 0)
            {
                continue;
            }

            depth--;
            if (depth == 0 && start >= 0)
            {
                result.Add(text[start..(i + 1)]);
                start = -1;
            }
        }

        return result;
    }

    private static bool TryParseJson(string candidate, out JsonDocument? document, out string parseError)
    {
        document = null;
        parseError = string.Empty;
        try
        {
            document = JsonDocument.Parse(candidate);
            return true;
        }
        catch (Exception ex)
        {
            parseError = ex.Message;
            return false;
        }
    }

    private static string ToSingleLine(string text)
    {
        return WhiteSpaceRegex.Replace(text ?? string.Empty, " ").Trim();
    }
}
