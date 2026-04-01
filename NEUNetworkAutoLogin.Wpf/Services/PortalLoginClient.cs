using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class PortalLoginClient
{
    private const string TpassPublicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjA28DLKXZzxbKmo9/1WkVLf1mr+wtLXLXt6sC4WiBCtsbzF5ewm7ARZeAdS3iZtqlYPn6IcUoOw42H8nAK/tfFcIb6dZ1K0atn0U39oWCGPzYuKtLJeMuNZiDXVuAXtojrckOjLW9B3gUnaNGLuIx0fYe66l0o9WjU2cGLNZQfiIxs2h00z1EA9IdSnVxiVQWSD+lsP3JZXh2TT287la4Y4603SQNKTK/QvXfcmccwTEd1IW6HwGxD6QrkInBiHisKWxmveN7UDSaQRZ/J97G0YC32pD38WT53izXeK0p/kU/X37VP555um1wVWFvPIuc9I7gMP1+hq5a+X6c++tQIDAQAB";

    private static readonly Regex WhiteSpaceRegex = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex InputValueRegex = new(
        "<input[^>]*name=['\"](?<name>[^'\"]+)['\"][^>]*value=['\"](?<value>[^'\"]*)['\"][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ErrorMessageRegex = new(
        "id=['\"](?:errormsghide|errormsg)['\"][^>]*>(?<msg>[^<]+)<",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex IPv4Regex = new(@"^\d{1,3}(?:\.\d{1,3}){3}$", RegexOptions.Compiled);

    public PortalLoginClient(AppPaths _)
    {
    }

    public async Task<PortalLoginResult> LoginAsync(
        AppSettings settings,
        CredentialModel credential,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(credential.Username) || string.IsNullOrWhiteSpace(credential.Password))
        {
            return new PortalLoginResult
            {
                Success = false,
                Message = "账号或密码为空。"
            };
        }

        var trace = new List<string>();
        var urls = BuildUrls(settings);

        using var handler = CreateHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
        AddDefaultHeaders(client);

        try
        {
            var before = await ProbeOnlineStateAsync(client, urls, trace, "before-login", cancellationToken);
            if (before.Known && before.Online)
            {
                return new PortalLoginResult
                {
                    Success = true,
                    Message = "当前已是登录状态。",
                    FinalUrl = before.FinalUrl,
                    Trace = trace
                };
            }

            await LoadPageAsync(client, urls.PortalPageUrl, trace, "portal", cancellationToken);

            var loginPage = await LoadPageAsync(client, urls.TpassLoginUrl, trace, "tpass-login-page", cancellationToken);
            var lt = GetHiddenInputValue(loginPage.Body, "lt");
            var execution = GetHiddenInputValue(loginPage.Body, "execution");
            if (string.IsNullOrWhiteSpace(lt) || string.IsNullOrWhiteSpace(execution))
            {
                return new PortalLoginResult
                {
                    Success = false,
                    Message = "登录页缺少认证参数（lt/execution）。",
                    FinalUrl = loginPage.FinalUrl,
                    Trace = trace
                };
            }

            var rsa = EncryptCredentialForTpass(credential.Username.Trim(), credential.Password);
            var form = new Dictionary<string, string>
            {
                ["rsa"] = rsa,
                ["ul"] = credential.Username.Trim().Length.ToString(),
                ["pl"] = credential.Password.Length.ToString(),
                ["lt"] = lt,
                ["execution"] = execution,
                ["_eventId"] = "submit",
                ["t_un"] = string.Empty,
                ["t_pd"] = string.Empty,
                ["t_c"] = string.Empty
            };

            using var loginRequest = new HttpRequestMessage(HttpMethod.Post, urls.TpassLoginUrl)
            {
                Content = new FormUrlEncodedContent(form)
            };
            loginRequest.Headers.Referrer = urls.TpassLoginUrl;
            loginRequest.Headers.TryAddWithoutValidation("Origin", "https://pass.neu.edu.cn");

            using var loginResponse = await client.SendAsync(loginRequest, cancellationToken);
            var loginBody = await loginResponse.Content.ReadAsStringAsync(cancellationToken);

            var finalAfterPost = await FollowRedirectsAsync(
                client,
                urls.TpassLoginUrl,
                loginResponse,
                trace,
                "login-post",
                cancellationToken);
            trace.Add($"after-submit {finalAfterPost}");

            await ActivateTicketIfPresentAsync(client, finalAfterPost, settings.AcId, trace, cancellationToken);

            for (var i = 0; i < 8; i++)
            {
                var verify = await ProbeOnlineStateAsync(client, urls, trace, $"verify-login-{i + 1}", cancellationToken);
                if (verify.Known && verify.Online)
                {
                    return new PortalLoginResult
                    {
                        Success = true,
                        Message = "登录成功。",
                        FinalUrl = verify.FinalUrl,
                        Trace = trace
                    };
                }

                await Task.Delay(2000, cancellationToken);
            }

            var errorMessage = ExtractLoginError(loginBody);
            return new PortalLoginResult
            {
                Success = false,
                Message = string.IsNullOrWhiteSpace(errorMessage) ? "登录没有到达成功状态。" : errorMessage,
                FinalUrl = finalAfterPost,
                Trace = trace
            };
        }
        catch (OperationCanceledException)
        {
            return new PortalLoginResult
            {
                Success = false,
                Message = "登录超时，请稍后重试。",
                Trace = trace
            };
        }
        catch (Exception ex)
        {
            trace.Add($"login error={ToSingleLine(ex.Message)}");
            return new PortalLoginResult
            {
                Success = false,
                Message = "登录失败：" + ToSingleLine(ex.Message),
                Trace = trace
            };
        }
    }

    public async Task<PortalLoginResult> LogoutAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        var trace = new List<string>();
        var urls = BuildUrls(settings);

        using var handler = CreateHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(40) };
        AddDefaultHeaders(client);

        try
        {
            var before = await ProbeOnlineStateAsync(client, urls, trace, "before-logout", cancellationToken);
            if (before.Known && !before.Online)
            {
                return new PortalLoginResult
                {
                    Success = true,
                    Message = "当前已是未登录状态。",
                    FinalUrl = before.FinalUrl,
                    Trace = trace
                };
            }

            await LoadPageAsync(client, urls.SuccessPageUrl, trace, "success-page", cancellationToken);

            var logoutUser = before.Username;
            var logoutIp = before.OnlineIp;
            if (string.IsNullOrWhiteSpace(logoutUser) || string.IsNullOrWhiteSpace(logoutIp))
            {
                var info = await FetchRadUserInfoAsync(client, urls, trace, "logout-info", cancellationToken);
                logoutUser = info.Username;
                logoutIp = info.OnlineIp;
            }

            if (!string.IsNullOrWhiteSpace(logoutUser) && !string.IsNullOrWhiteSpace(logoutIp))
            {
                var callback = BuildCallback();
                var logoutUrl = new UriBuilder(urls.PortalHttpBase)
                {
                    Path = "/cgi-bin/srun_portal",
                    Query =
                        $"callback={Uri.EscapeDataString(callback)}&action=logout&username={Uri.EscapeDataString(logoutUser)}&ip={Uri.EscapeDataString(logoutIp)}&ac_id={settings.AcId}&_={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
                }.Uri;

                using var logoutResponse = await client.GetAsync(logoutUrl, cancellationToken);
                var logoutBody = await logoutResponse.Content.ReadAsStringAsync(cancellationToken);
                var apiOk = IsLogoutApiOk(logoutBody);
                trace.Add($"logout-api status={(int)logoutResponse.StatusCode} responseOk={apiOk} url={logoutUrl}");
            }
            else
            {
                trace.Add("logout-api skip (missing username or ip)");
            }

            await Task.Delay(1200, cancellationToken);
            var afterApi = await ProbeOnlineStateAsync(client, urls, trace, "after-logout-api", cancellationToken);
            if (afterApi.Known && !afterApi.Online)
            {
                return new PortalLoginResult
                {
                    Success = true,
                    Message = "已注销校园网登录。",
                    FinalUrl = afterApi.FinalUrl,
                    Trace = trace
                };
            }

            await LoadPageAsync(client, urls.TpassLogoutUrl, trace, "tpass-logout", cancellationToken);
            await Task.Delay(1000, cancellationToken);

            var afterCas = await ProbeOnlineStateAsync(client, urls, trace, "after-cas-logout", cancellationToken);
            if (afterCas.Known && !afterCas.Online)
            {
                return new PortalLoginResult
                {
                    Success = true,
                    Message = "已注销校园网登录。",
                    FinalUrl = afterCas.FinalUrl,
                    Trace = trace
                };
            }

            return new PortalLoginResult
            {
                Success = false,
                Message = afterCas.Known ? "注销后仍检测为在线状态。" : "注销状态未知，请重试。",
                FinalUrl = afterCas.FinalUrl,
                Trace = trace
            };
        }
        catch (OperationCanceledException)
        {
            return new PortalLoginResult
            {
                Success = false,
                Message = "注销超时，请稍后重试。",
                Trace = trace
            };
        }
        catch (Exception ex)
        {
            trace.Add($"logout error={ToSingleLine(ex.Message)}");
            return new PortalLoginResult
            {
                Success = false,
                Message = "注销失败：" + ToSingleLine(ex.Message),
                Trace = trace
            };
        }
    }

    private static HttpClientHandler CreateHandler()
    {
        return new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            CookieContainer = new CookieContainer(),
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
    }

    private static void AddDefaultHeaders(HttpClient client)
    {
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
    }

    private static async Task<PageSnapshot> LoadPageAsync(
        HttpClient client,
        Uri startUrl,
        List<string> trace,
        string tag,
        CancellationToken cancellationToken)
    {
        var current = startUrl;
        for (var hop = 0; hop < 12; hop++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            using var response = await client.SendAsync(request, cancellationToken);
            if (IsRedirect(response.StatusCode) && response.Headers.Location is not null)
            {
                current = ToAbsoluteUri(current, response.Headers.Location);
                trace.Add($"{tag}-redirect {(int)response.StatusCode} => {current}");
                continue;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            trace.Add($"{tag} {current}");
            return new PageSnapshot(current.ToString(), body, response.StatusCode);
        }

        trace.Add($"{tag} too-many-redirects");
        return new PageSnapshot(current.ToString(), string.Empty, HttpStatusCode.Redirect);
    }

    private static async Task<string> FollowRedirectsAsync(
        HttpClient client,
        Uri requestUrl,
        HttpResponseMessage initialResponse,
        List<string> trace,
        string tag,
        CancellationToken cancellationToken)
    {
        var current = requestUrl;
        if (!IsRedirect(initialResponse.StatusCode) || initialResponse.Headers.Location is null)
        {
            return current.ToString();
        }

        current = ToAbsoluteUri(current, initialResponse.Headers.Location);
        trace.Add($"{tag}-redirect {(int)initialResponse.StatusCode} => {current}");

        for (var hop = 0; hop < 12; hop++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            using var response = await client.SendAsync(request, cancellationToken);
            if (IsRedirect(response.StatusCode) && response.Headers.Location is not null)
            {
                current = ToAbsoluteUri(current, response.Headers.Location);
                trace.Add($"{tag}-redirect {(int)response.StatusCode} => {current}");
                continue;
            }

            return current.ToString();
        }

        trace.Add($"{tag}-too-many-redirects");
        return current.ToString();
    }

    private static async Task<ProbeResult> ProbeOnlineStateAsync(
        HttpClient client,
        UrlBundle urls,
        List<string> trace,
        string tag,
        CancellationToken cancellationToken)
    {
        var api = await FetchRadUserInfoAsync(client, urls, trace, tag, cancellationToken);
        if (api.Known)
        {
            return api;
        }

        var successPage = await LoadPageAsync(client, urls.SuccessPageUrl, trace, $"{tag}-page", cancellationToken);
        var body = successPage.Body;
        var online = IsConnectedPage(successPage.FinalUrl, body);
        var login = IsLoginPage(body);
        var known = online || login;
        trace.Add($"{tag}-page known={known} online={online} url={successPage.FinalUrl}");

        return new ProbeResult(
            known,
            online,
            "page",
            string.Empty,
            string.Empty,
            successPage.FinalUrl);
    }

    private static async Task<ProbeResult> FetchRadUserInfoAsync(
        HttpClient client,
        UrlBundle urls,
        List<string> trace,
        string tag,
        CancellationToken cancellationToken)
    {
        var callback = BuildCallback();
        var builder = new UriBuilder(urls.PortalBase)
        {
            Path = "/cgi-bin/rad_user_info",
            Query = $"callback={Uri.EscapeDataString(callback)}&_={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
        };

        try
        {
            using var response = await client.GetAsync(builder.Uri, cancellationToken);
            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            var parsed = ParseRadUserInfo(text);
            trace.Add(
                $"{tag}-rad status={(int)response.StatusCode} known={parsed.Known} online={parsed.Online} source={parsed.Source} user={Fallback(parsed.Username)} ip={Fallback(parsed.OnlineIp)}");

            return parsed with { FinalUrl = builder.Uri.ToString() };
        }
        catch (Exception ex)
        {
            trace.Add($"{tag}-rad error={ToSingleLine(ex.Message)}");
            return new ProbeResult(false, false, "request-error", string.Empty, string.Empty, string.Empty);
        }
    }

    private static ProbeResult ParseRadUserInfo(string text)
    {
        var raw = (text ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new ProbeResult(false, false, "empty", string.Empty, string.Empty, string.Empty);
        }

        if (raw.IndexOf("not_online_error", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return new ProbeResult(true, false, "not-online", string.Empty, string.Empty, string.Empty);
        }

        var csv = ParseCsvOnlineInfo(raw);
        if (csv.Known)
        {
            return csv;
        }

        var jsonText = ExtractJsonPayload(raw);
        if (string.IsNullOrWhiteSpace(jsonText))
        {
            return new ProbeResult(false, false, "unknown-format", string.Empty, string.Empty, string.Empty);
        }

        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new ProbeResult(false, false, "unknown-format", string.Empty, string.Empty, string.Empty);
            }

            var error = GetPropertyString(root, "error");
            if (string.IsNullOrWhiteSpace(error))
            {
                error = GetPropertyString(root, "res");
            }
            error = error.ToLowerInvariant();

            var username = FirstNonEmpty(
                GetPropertyString(root, "username"),
                GetPropertyString(root, "user_name"),
                GetPropertyString(root, "user"),
                GetPropertyString(root, "uid"),
                GetPropertyString(root, "billing_id"));

            var onlineIp = FirstNonEmpty(
                GetPropertyString(root, "online_ip"),
                GetPropertyString(root, "client_ip"),
                GetPropertyString(root, "ip"));

            if (error.Contains("not_online_error", StringComparison.Ordinal))
            {
                return new ProbeResult(true, false, "jsonp-not-online", username, onlineIp, string.Empty);
            }

            if (error == "ok" || IsLikelyIPv4(onlineIp))
            {
                return new ProbeResult(true, true, "jsonp-online", username, onlineIp, string.Empty);
            }

            return new ProbeResult(false, false, "jsonp-unknown", username, onlineIp, string.Empty);
        }
        catch
        {
            return new ProbeResult(false, false, "parse-error", string.Empty, string.Empty, string.Empty);
        }
    }

    private static ProbeResult ParseCsvOnlineInfo(string raw)
    {
        var parts = raw.Split(',');
        if (parts.Length < 9)
        {
            return new ProbeResult(false, false, "csv", string.Empty, string.Empty, string.Empty);
        }

        var username = parts[0].Trim();
        var ip = parts[8].Trim();
        if (string.IsNullOrWhiteSpace(username) || !IsLikelyIPv4(ip))
        {
            return new ProbeResult(false, false, "csv", string.Empty, string.Empty, string.Empty);
        }

        return new ProbeResult(true, true, "csv", username, ip, string.Empty);
    }

    private static bool IsLogoutApiOk(string responseText)
    {
        var jsonText = ExtractJsonPayload(responseText);
        if (string.IsNullOrWhiteSpace(jsonText))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            var error = FirstNonEmpty(GetPropertyString(root, "error"), GetPropertyString(root, "res"));
            return string.Equals(error, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task ActivateTicketIfPresentAsync(
        HttpClient client,
        string finalAfterPost,
        int fallbackAcId,
        List<string> trace,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(finalAfterPost, UriKind.Absolute, out var finalUri))
        {
            return;
        }

        if (!finalUri.AbsolutePath.Contains("srun_portal_sso", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var ticket = GetQueryValue(finalUri, "ticket");
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return;
        }

        var acIdRaw = GetQueryValue(finalUri, "ac_id");
        var acId = int.TryParse(acIdRaw, out var parsedAcId) && parsedAcId > 0 ? parsedAcId : fallbackAcId;

        var activateUrl = new UriBuilder(finalUri)
        {
            Path = "/v1/srun_portal_sso",
            Query = $"ac_id={acId}&ticket={Uri.EscapeDataString(ticket)}"
        }.Uri;

        using var response = await client.GetAsync(activateUrl, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var bodySingleLine = ToSingleLine(body);
        if (bodySingleLine.Length > 160)
        {
            bodySingleLine = bodySingleLine[..160];
        }
        trace.Add($"ticket-activate status={(int)response.StatusCode} url={activateUrl} body={bodySingleLine}");

        var successUrl = new UriBuilder(finalUri)
        {
            Path = "/srun_portal_success",
            Query = $"ac_id={acId}&theme=pro"
        }.Uri;
        await LoadPageAsync(client, successUrl, trace, "ticket-success-page", cancellationToken);
    }

    private static string ExtractLoginError(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var match = ErrorMessageRegex.Match(html);
        return match.Success ? ToSingleLine(WebUtility.HtmlDecode(match.Groups["msg"].Value)) : string.Empty;
    }

    private static string EncryptCredentialForTpass(string username, string password)
    {
        var plainText = username + password;
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(TpassPublicKey), out _);
        var encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(encrypted);
    }

    private static UrlBundle BuildUrls(AppSettings settings)
    {
        var portalBase = NormalizePortalHost(settings.PortalHost);
        var portalHttpBase = new UriBuilder(portalBase)
        {
            Scheme = Uri.UriSchemeHttp,
            Port = portalBase.IsDefaultPort ? -1 : portalBase.Port
        }.Uri;

        var portalPageUrl = new UriBuilder(portalBase)
        {
            Path = "/srun_portal_pc",
            Query = $"ac_id={settings.AcId}&theme=pro"
        }.Uri;

        var successPageUrl = new UriBuilder(portalBase)
        {
            Path = "/srun_portal_success",
            Query = $"ac_id={settings.AcId}&theme=pro"
        }.Uri;

        var serviceUrl = BuildServiceUrl(settings, portalHttpBase);
        var tpassLoginUrl = new Uri("https://pass.neu.edu.cn/tpass/login?service=" + Uri.EscapeDataString(serviceUrl.ToString()));
        var tpassLogoutUrl = new Uri("https://pass.neu.edu.cn/tpass/logout?service=" + Uri.EscapeDataString(portalBase.ToString()));

        return new UrlBundle(portalBase, portalHttpBase, portalPageUrl, successPageUrl, serviceUrl, tpassLoginUrl, tpassLogoutUrl);
    }

    private static Uri BuildServiceUrl(AppSettings settings, Uri portalHttpBase)
    {
        Uri serviceUri;
        if (!string.IsNullOrWhiteSpace(settings.ServiceBaseUrl) &&
            Uri.TryCreate(settings.ServiceBaseUrl.Trim(), UriKind.Absolute, out var custom))
        {
            serviceUri = custom;
        }
        else
        {
            serviceUri = new Uri(portalHttpBase, "/srun_portal_sso");
        }

        if (serviceUri.Host.Contains("ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase) &&
            serviceUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            serviceUri = new UriBuilder(serviceUri)
            {
                Scheme = Uri.UriSchemeHttp,
                Port = serviceUri.IsDefaultPort ? -1 : serviceUri.Port
            }.Uri;
        }

        var withAcId = serviceUri.ToString();
        if (!Regex.IsMatch(withAcId, @"(?:\?|&)ac_id=", RegexOptions.IgnoreCase))
        {
            withAcId += withAcId.Contains('?', StringComparison.Ordinal) ? "&" : "?";
            withAcId += "ac_id=" + settings.AcId;
        }

        return new Uri(withAcId);
    }

    private static Uri NormalizePortalHost(string input)
    {
        var host = string.IsNullOrWhiteSpace(input) ? "https://ipgw.neu.edu.cn/" : input.Trim();
        if (!host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            host = "https://" + host;
        }

        if (host.StartsWith("http://ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase))
        {
            host = "https://" + host["http://".Length..];
        }

        if (!host.EndsWith("/", StringComparison.Ordinal))
        {
            host += "/";
        }

        return new Uri(host);
    }

    private static bool IsConnectedPage(string url, string body)
    {
        var u = url ?? string.Empty;
        var content = body ?? string.Empty;
        return u.Contains("srun_portal_success", StringComparison.OrdinalIgnoreCase)
               || content.Contains("id=\"logout\"", StringComparison.OrdinalIgnoreCase)
               || content.Contains("id=\"logout-all\"", StringComparison.OrdinalIgnoreCase)
               || content.Contains("logout-all-success", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLoginPage(string body)
    {
        var content = body ?? string.Empty;
        return content.Contains("id=\"login-sso\"", StringComparison.OrdinalIgnoreCase)
               || content.Contains("id=\"login-account\"", StringComparison.OrdinalIgnoreCase)
               || content.Contains("id=\"loginForm\"", StringComparison.OrdinalIgnoreCase)
               || content.Contains("id=\"index_login_btn\"", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetHiddenInputValue(string html, string inputName)
    {
        if (string.IsNullOrWhiteSpace(html) || string.IsNullOrWhiteSpace(inputName))
        {
            return string.Empty;
        }

        foreach (Match match in InputValueRegex.Matches(html))
        {
            var name = match.Groups["name"].Value;
            if (!string.Equals(name, inputName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return WebUtility.HtmlDecode(match.Groups["value"].Value);
        }

        return string.Empty;
    }

    private static Uri ToAbsoluteUri(Uri current, Uri next)
    {
        return next.IsAbsoluteUri ? next : new Uri(current, next);
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        return code is 301 or 302 or 303 or 307 or 308;
    }

    private static string ExtractJsonPayload(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var text = raw.Trim();
        var firstParen = text.IndexOf('(');
        var lastParen = text.LastIndexOf(')');
        if (firstParen > 0 && lastParen > firstParen)
        {
            return text[(firstParen + 1)..lastParen].Trim();
        }

        if (text.StartsWith("{", StringComparison.Ordinal) && text.EndsWith("}", StringComparison.Ordinal))
        {
            return text;
        }

        return string.Empty;
    }

    private static string GetPropertyString(JsonElement root, string propertyName)
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

    private static bool IsLikelyIPv4(string value)
    {
        return !string.IsNullOrWhiteSpace(value) && IPv4Regex.IsMatch(value);
    }

    private static string GetQueryValue(Uri uri, string name)
    {
        if (uri is null || string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        var query = uri.Query;
        if (string.IsNullOrWhiteSpace(query))
        {
            return string.Empty;
        }

        var trimmed = query.TrimStart('?');
        var parts = trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var equalIndex = part.IndexOf('=');
            if (equalIndex <= 0)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(part[..equalIndex]);
            if (!string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return Uri.UnescapeDataString(part[(equalIndex + 1)..]);
        }

        return string.Empty;
    }

    private static string BuildCallback()
    {
        return "cb_" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + "_" + Random.Shared.Next(100000, 999999);
    }

    private static string FirstNonEmpty(params string[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static string Fallback(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "-" : value;
    }

    private static string ToSingleLine(string text)
    {
        return WhiteSpaceRegex.Replace(text ?? string.Empty, " ").Trim();
    }

    private sealed record UrlBundle(
        Uri PortalBase,
        Uri PortalHttpBase,
        Uri PortalPageUrl,
        Uri SuccessPageUrl,
        Uri ServiceUrl,
        Uri TpassLoginUrl,
        Uri TpassLogoutUrl);

    private sealed record PageSnapshot(
        string FinalUrl,
        string Body,
        HttpStatusCode StatusCode);

    private sealed record ProbeResult(
        bool Known,
        bool Online,
        string Source,
        string Username,
        string OnlineIp,
        string FinalUrl);
}
