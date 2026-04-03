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
    private static readonly Regex ActivateUrlRegex = new(
        @"(?<url>(?:https?:)?//[^'""\s<>]*srun_portal_sso[^'""\s<>]*|/[^'""\s<>]*srun_portal_sso[^'""\s<>]*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ConnectUrlRegex = new(
        @"(?<url>(?:https?:)?//[^'""\s<>]*(?:v1/srun_portal_sso|srun_portal_sso)[^'""\s<>]*|/[^'""\s<>]*(?:v1/srun_portal_sso|srun_portal_sso)[^'""\s<>]*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public PortalLoginClient(AppPaths _)
    {
    }

    public async Task<PortalLoginResult> LoginAsync(
        AppSettings settings,
        CredentialModel credential,
        CancellationToken cancellationToken,
        bool isWireless = false)
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
        var urls = BuildUrls(settings, isWireless);
        trace.Add($"service-url {urls.ServiceUrl}");
        trace.Add(isWireless ? "auth-mode wireless-legacy" : "auth-mode wired-unified");

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

            var activated = await ActivateTicketIfPresentAsync(client, urls, finalAfterPost, settings.AcId, trace, cancellationToken, isWireless);
            if (!isWireless && !activated)
            {
                await TryPortalConnectStepAsync(client, urls, settings.AcId, trace, cancellationToken);
            }

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
        var urls = BuildUrls(settings, isWireless: false);

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
        var previous = requestUrl;
        if (!IsRedirect(initialResponse.StatusCode) || initialResponse.Headers.Location is null)
        {
            return current.ToString();
        }

        current = ToAbsoluteUri(current, initialResponse.Headers.Location);
        trace.Add($"{tag}-redirect {(int)initialResponse.StatusCode} => {current}");

        for (var hop = 0; hop < 12; hop++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            if (previous.Scheme is "http" or "https")
            {
                request.Headers.Referrer = previous;
            }

            using var response = await client.SendAsync(request, cancellationToken);
            if (IsRedirect(response.StatusCode) && response.Headers.Location is not null)
            {
                previous = current;
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

    private static async Task<bool> ActivateTicketIfPresentAsync(
        HttpClient client,
        UrlBundle urls,
        string finalAfterPost,
        int fallbackAcId,
        List<string> trace,
        CancellationToken cancellationToken,
        bool isWireless)
    {
        if (!Uri.TryCreate(finalAfterPost, UriKind.Absolute, out var finalUri))
        {
            return false;
        }

        if (!finalUri.AbsolutePath.Contains("srun_portal_sso", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var ticket = GetQueryValue(finalUri, "ticket");
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return false;
        }

        var acIdRaw = GetQueryValue(finalUri, "ac_id");
        var parsedAcId = int.TryParse(acIdRaw, out var parsed) && parsed > 0 ? parsed : 0;
        var acId = parsedAcId > 0 ? parsedAcId : fallbackAcId;
        var acIdCandidates = BuildAcIdCandidates(acId, fallbackAcId, 1);

        var activateCandidates = isWireless
            ? BuildWirelessLegacyTicketActivateCandidates(finalUri, acId)
            : BuildTicketActivateCandidates(finalUri, urls, acIdCandidates, ticket);
        var activateOk = false;
        Uri? activatedOn = null;

        for (var i = 0; i < activateCandidates.Count; i++)
        {
            var activateUrl = activateCandidates[i];
            using var request = new HttpRequestMessage(HttpMethod.Get, activateUrl);
            if (finalUri.Scheme is "http" or "https")
            {
                request.Headers.Referrer = finalUri;
            }
            request.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            var bodySingleLine = ToSingleLine(body);
            if (bodySingleLine.Length > 180)
            {
                bodySingleLine = bodySingleLine[..180];
            }

            var ok = IsTicketActivateOk(body);
            trace.Add($"ticket-activate[{i + 1}/{activateCandidates.Count}] status={(int)response.StatusCode} ok={ok} ac_ids={string.Join("/", acIdCandidates)} url={activateUrl} body={bodySingleLine}");

            if (!isWireless && !ok && activateCandidates.Count < 16 && LooksLikeHtml(body))
            {
                var discovered = ExtractTicketActivateCandidatesFromHtml(activateUrl, body);
                var added = 0;
                foreach (var discoveredUrl in discovered)
                {
                    if (AddCandidate(activateCandidates, discoveredUrl))
                    {
                        added++;
                    }
                }

                if (added > 0)
                {
                    trace.Add($"ticket-activate-discovered from={activateUrl} added={added}");
                }
            }

            if (ok)
            {
                activateOk = true;
                activatedOn = activateUrl;
                break;
            }
        }

        var successBase = activatedOn ?? finalUri;
        var successUrl = new UriBuilder(successBase)
        {
            Path = "/srun_portal_success",
            Query = $"ac_id={acId}&theme=pro"
        }.Uri;
        await LoadPageAsync(client, successUrl, trace, activateOk ? "ticket-success-page" : "ticket-success-page-fallback", cancellationToken);
        return activateOk;
    }

    private static List<Uri> BuildWirelessLegacyTicketActivateCandidates(Uri finalUri, int acId)
    {
        var candidates = new List<Uri>();
        var query = $"ac_id={acId}&ticket={Uri.EscapeDataString(GetQueryValue(finalUri, "ticket"))}";

        AddCandidate(candidates, new UriBuilder(finalUri)
        {
            Path = "/v1/srun_portal_sso",
            Query = query
        }.Uri);

        var alternateScheme = finalUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? Uri.UriSchemeHttp
            : Uri.UriSchemeHttps;

        AddCandidate(candidates, new UriBuilder(finalUri)
        {
            Scheme = alternateScheme,
            Port = -1,
            Path = "/v1/srun_portal_sso",
            Query = query
        }.Uri);

        return candidates;
    }

    private static List<Uri> BuildTicketActivateCandidates(Uri finalUri, UrlBundle urls, List<int> acIdCandidates, string ticket)
    {
        var candidates = new List<Uri>();
        var queries = BuildTicketQueries(acIdCandidates, ticket);

        var baseAuthorities = new[]
        {
            new UriBuilder(finalUri) { Path = "/", Query = string.Empty }.Uri,
            new UriBuilder(urls.PortalBase) { Path = "/", Query = string.Empty }.Uri
        };

        foreach (var authority in baseAuthorities)
        {
            var alternateScheme = authority.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? Uri.UriSchemeHttp
                : Uri.UriSchemeHttps;

            var schemes = new[] { authority.Scheme, alternateScheme };
            foreach (var scheme in schemes)
            {
                foreach (var query in queries)
                {
                    AddCandidate(candidates, new UriBuilder(authority)
                    {
                        Scheme = scheme,
                        Port = -1,
                        Path = "/v1/srun_portal_sso",
                        Query = query
                    }.Uri);
                }
            }
        }

        return candidates;
    }

    private static async Task<bool> TryPortalConnectStepAsync(
        HttpClient client,
        UrlBundle urls,
        int acId,
        List<string> trace,
        CancellationToken cancellationToken)
    {
        trace.Add("connect-step begin");

        var pageCandidates = new List<Uri>
        {
            urls.PortalPageUrl,
            new UriBuilder(urls.PortalHttpBase)
            {
                Path = "/srun_portal_pc",
                Query = $"ac_id={acId}&theme=pro"
            }.Uri,
            new UriBuilder(urls.PortalBase)
            {
                Path = "/srun_portal_pc",
                Query = "ac_id=1&theme=pro"
            }.Uri,
            new UriBuilder(urls.PortalHttpBase)
            {
                Path = "/srun_portal_pc",
                Query = "ac_id=1&theme=pro"
            }.Uri
        };

        for (var pageIndex = 0; pageIndex < pageCandidates.Count; pageIndex++)
        {
            var page = await LoadPageAsync(client, pageCandidates[pageIndex], trace, $"connect-page-{pageIndex + 1}", cancellationToken);
            if (!Uri.TryCreate(page.FinalUrl, UriKind.Absolute, out var pageUri))
            {
                continue;
            }

            var pageAcIdRaw = GetQueryValue(pageUri, "ac_id");
            var pageAcId = int.TryParse(pageAcIdRaw, out var parsedPageAcId) && parsedPageAcId > 0 ? parsedPageAcId : 0;
            var actionAcIds = BuildAcIdCandidates(acId, pageAcId, 1);
            trace.Add($"connect-page-acid page={pageUri} candidates={string.Join('/', actionAcIds)}");

            var connectCandidates = BuildConnectActionCandidatesFromHtml(pageUri, page.Body, urls, actionAcIds);
            if (connectCandidates.Count == 0)
            {
                trace.Add($"connect-step no action candidates from page {page.FinalUrl}");
                continue;
            }

            for (var i = 0; i < connectCandidates.Count; i++)
            {
                var actionUrl = connectCandidates[i];
                using var request = new HttpRequestMessage(HttpMethod.Get, actionUrl);
                request.Headers.Referrer = pageUri;
                request.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
                using var response = await client.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                var bodySingleLine = ToSingleLine(body);
                if (bodySingleLine.Length > 180)
                {
                    bodySingleLine = bodySingleLine[..180];
                }

                var ok = IsPortalConnectActionOk(body);
                trace.Add($"connect-action[{i + 1}/{connectCandidates.Count}] status={(int)response.StatusCode} ok={ok} url={actionUrl} body={bodySingleLine}");

                var redirect = ExtractRedirectFromPortalAction(body, actionUrl);
                if (redirect is not null)
                {
                    var follow = await LoadPageAsync(client, redirect, trace, $"connect-follow-{i + 1}", cancellationToken);
                    trace.Add($"connect-follow-{i + 1} final={follow.FinalUrl}");

                    var activated = await ActivateTicketIfPresentAsync(client, urls, follow.FinalUrl, actionAcIds.FirstOrDefault(), trace, cancellationToken, isWireless: false);
                    if (activated)
                    {
                        var redirectedVerify = await ProbeOnlineStateAsync(client, urls, trace, $"connect-follow-verify-{i + 1}", cancellationToken);
                        if (redirectedVerify.Known && redirectedVerify.Online)
                        {
                            trace.Add("connect-step online confirmed after redirect follow");
                            return true;
                        }
                    }
                }

                var verify = await ProbeOnlineStateAsync(client, urls, trace, $"connect-verify-{i + 1}", cancellationToken);
                if (verify.Known && verify.Online)
                {
                    trace.Add("connect-step online confirmed");
                    return true;
                }
            }
        }

        trace.Add("connect-step finished without online confirmation");
        return false;
    }

    private static List<Uri> BuildConnectActionCandidatesFromHtml(Uri pageUri, string html, UrlBundle urls, List<int> acIdCandidates)
    {
        var results = new List<Uri>();
        var decoded = WebUtility.HtmlDecode(html ?? string.Empty).Replace(@"\/", "/", StringComparison.Ordinal);

        foreach (Match match in ConnectUrlRegex.Matches(decoded))
        {
            var raw = match.Groups["url"].Value.Trim();
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (raw.StartsWith("//", StringComparison.Ordinal))
            {
                raw = $"{pageUri.Scheme}:{raw}";
            }

            Uri? candidate = null;
            if (Uri.TryCreate(raw, UriKind.Absolute, out var absolute))
            {
                candidate = absolute;
            }
            else if (Uri.TryCreate(pageUri, raw, out var relative))
            {
                candidate = relative;
            }

            if (candidate is null)
            {
                continue;
            }

            candidate = NormalizeConnectActionUrl(candidate, acIdCandidates.FirstOrDefault());
            if (candidate is not null)
            {
                AddCandidate(results, candidate);
            }
        }

        foreach (var acId in acIdCandidates)
        {
            if (acId <= 0)
            {
                continue;
            }

            AddCandidate(results, new UriBuilder(urls.PortalHttpBase)
            {
                Path = "/v1/srun_portal_sso",
                Query = $"ac_id={acId}&_={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
            }.Uri);
            AddCandidate(results, new UriBuilder(urls.PortalBase)
            {
                Path = "/v1/srun_portal_sso",
                Query = $"ac_id={acId}&_={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
            }.Uri);
        }

        return results;
    }

    private static Uri? NormalizeConnectActionUrl(Uri input, int acId)
    {
        if (!input.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            !input.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (input.AbsolutePath.Contains("/cgi-bin/srun_portal", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!input.AbsolutePath.Contains("/v1/srun_portal_sso", StringComparison.OrdinalIgnoreCase) &&
            !input.AbsolutePath.Contains("/srun_portal_sso", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var query = ParseQueryString(input.Query);

        if (!query.ContainsKey("ac_id") && acId > 0)
        {
            query["ac_id"] = acId.ToString();
        }

        if (!query.ContainsKey("_"))
        {
            query["_"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        }

        return new UriBuilder(input)
        {
            Query = BuildQueryString(query)
        }.Uri;
    }

    private static bool IsPortalConnectActionOk(string responseText)
    {
        var jsonText = ExtractJsonPayload(responseText);
        if (!string.IsNullOrWhiteSpace(jsonText))
        {
            try
            {
                using var doc = JsonDocument.Parse(jsonText);
                var root = doc.RootElement;
                var codeText = GetPropertyString(root, "code");
                if (int.TryParse(codeText, out var code) && code == 0)
                {
                    return true;
                }

                var error = FirstNonEmpty(
                    GetPropertyString(root, "error"),
                    GetPropertyString(root, "res"),
                    GetPropertyString(root, "message"));
                if (string.Equals(error, "ok", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(error, "success", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch
            {
            }
        }

        var text = responseText ?? string.Empty;
        return text.Contains("success", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("ok", StringComparison.OrdinalIgnoreCase);
    }

    private static Uri? ExtractRedirectFromPortalAction(string responseText, Uri baseUri)
    {
        var jsonText = ExtractJsonPayload(responseText);
        if (string.IsNullOrWhiteSpace(jsonText))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            var redirect = FirstNonEmpty(
                GetPropertyString(root, "Redirect"),
                GetPropertyString(root, "redirect"),
                GetPropertyString(root, "url"));
            if (string.IsNullOrWhiteSpace(redirect))
            {
                return null;
            }

            if (Uri.TryCreate(redirect, UriKind.Absolute, out var absolute))
            {
                return absolute;
            }

            return Uri.TryCreate(baseUri, redirect, out var relative) ? relative : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool AddCandidate(List<Uri> list, Uri uri)
    {
        if (list.Any(x =>
                string.Equals(x.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Host, uri.Host, StringComparison.OrdinalIgnoreCase) &&
                x.Port == uri.Port &&
                string.Equals(x.PathAndQuery, uri.PathAndQuery, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        list.Add(uri);
        return true;
    }

    private static bool LooksLikeHtml(string body)
    {
        return !string.IsNullOrWhiteSpace(body) &&
               body.Contains("<html", StringComparison.OrdinalIgnoreCase);
    }

    private static List<Uri> ExtractTicketActivateCandidatesFromHtml(Uri baseUri, string html)
    {
        var results = new List<Uri>();
        if (string.IsNullOrWhiteSpace(html))
        {
            return results;
        }

        var decoded = WebUtility.HtmlDecode(html).Replace(@"\/", "/", StringComparison.Ordinal);
        foreach (Match match in ActivateUrlRegex.Matches(decoded))
        {
            var raw = match.Groups["url"].Value.Trim();
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (raw.StartsWith("//", StringComparison.Ordinal))
            {
                raw = $"{baseUri.Scheme}:{raw}";
            }

            Uri? candidate = null;
            if (Uri.TryCreate(raw, UriKind.Absolute, out var absolute))
            {
                candidate = absolute;
            }
            else if (Uri.TryCreate(baseUri, raw, out var relative))
            {
                candidate = relative;
            }

            if (candidate is null)
            {
                continue;
            }

            if (!candidate.PathAndQuery.Contains("ticket=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (AddCandidate(results, candidate) && candidate.Scheme is "http" or "https")
            {
                var alternateScheme = candidate.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                    ? Uri.UriSchemeHttp
                    : Uri.UriSchemeHttps;
                var alternate = new UriBuilder(candidate)
                {
                    Scheme = alternateScheme,
                    Port = -1
                }.Uri;
                AddCandidate(results, alternate);
            }
        }

        return results;
    }

    private static bool IsTicketActivateOk(string responseText)
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
            if (root.TryGetProperty("code", out var codeElement))
            {
                if (codeElement.ValueKind == JsonValueKind.Number && codeElement.TryGetInt32(out var code) && code == 0)
                {
                    return true;
                }

                if (codeElement.ValueKind == JsonValueKind.String &&
                    int.TryParse(codeElement.GetString(), out var codeString) &&
                    codeString == 0)
                {
                    return true;
                }
            }

            var message = FirstNonEmpty(
                GetPropertyString(root, "message"),
                GetPropertyString(root, "res"),
                GetPropertyString(root, "error"));

            return string.Equals(message, "success", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(message, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
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

    private static UrlBundle BuildUrls(AppSettings settings, bool isWireless)
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

        var serviceUrl = BuildServiceUrl(settings, portalBase, isWireless);
        var tpassLoginUrl = new Uri("https://pass.neu.edu.cn/tpass/login?service=" + Uri.EscapeDataString(serviceUrl.ToString()));
        var tpassLogoutUrl = new Uri("https://pass.neu.edu.cn/tpass/logout?service=" + Uri.EscapeDataString(portalBase.ToString()));

        return new UrlBundle(portalBase, portalHttpBase, portalPageUrl, successPageUrl, serviceUrl, tpassLoginUrl, tpassLogoutUrl);
    }

    private static Uri BuildServiceUrl(AppSettings settings, Uri portalBase, bool isWireless)
    {
        Uri serviceUri;
        if (!string.IsNullOrWhiteSpace(settings.ServiceBaseUrl) &&
            Uri.TryCreate(settings.ServiceBaseUrl.Trim(), UriKind.Absolute, out var custom))
        {
            serviceUri = custom;
        }
        else
        {
            serviceUri = new Uri(portalBase, "/srun_portal_sso");
        }

        // Wireless keeps legacy HTTP service style. Wired prefers HTTPS.
        if (serviceUri.Host.Contains("ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase) &&
            isWireless &&
            serviceUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            serviceUri = new UriBuilder(serviceUri)
            {
                Scheme = Uri.UriSchemeHttp,
                Port = serviceUri.IsDefaultPort ? -1 : serviceUri.Port
            }.Uri;
        }

        if (serviceUri.Host.Contains("ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase) &&
            !isWireless &&
            serviceUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            serviceUri = new UriBuilder(serviceUri)
            {
                Scheme = Uri.UriSchemeHttps,
                Port = serviceUri.IsDefaultPort ? -1 : serviceUri.Port
            }.Uri;
        }

        // If custom service points to the same host as portal host, align scheme with portal host.
        if (string.Equals(serviceUri.Host, portalBase.Host, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(serviceUri.Scheme, portalBase.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            serviceUri = new UriBuilder(serviceUri)
            {
                Scheme = portalBase.Scheme,
                Port = portalBase.IsDefaultPort ? -1 : portalBase.Port
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

    private static List<int> BuildAcIdCandidates(params int[] values)
    {
        var list = new List<int>();
        foreach (var value in values)
        {
            if (value <= 0 || list.Contains(value))
            {
                continue;
            }

            list.Add(value);
        }

        return list;
    }

    private static List<string> BuildTicketQueries(List<int> acIdCandidates, string ticket)
    {
        var queries = new List<string>();
        var encodedTicket = Uri.EscapeDataString(ticket);

        queries.Add($"ticket={encodedTicket}");
        foreach (var acId in acIdCandidates)
        {
            if (acId <= 0)
            {
                continue;
            }

            queries.Add($"ac_id={acId}&ticket={encodedTicket}");
        }

        return queries;
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return map;
        }

        var trimmed = query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return map;
        }

        var parts = trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var index = part.IndexOf('=');
            if (index <= 0)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(part[..index]);
            var value = Uri.UnescapeDataString(part[(index + 1)..]);
            if (!string.IsNullOrWhiteSpace(key))
            {
                map[key] = value;
            }
        }

        return map;
    }

    private static string BuildQueryString(Dictionary<string, string> query)
    {
        return string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value ?? string.Empty)}"));
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
