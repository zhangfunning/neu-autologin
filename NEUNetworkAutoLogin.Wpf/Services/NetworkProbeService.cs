using System.Net.Http;
using System.Text.RegularExpressions;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class NetworkProbeService
{
    private static readonly Regex RedirectRegex = new(@"location\.href=['""](?<url>[^'""]+)['""]", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex AcIdRegex = new(@"index_(?<id>\d+)\.html", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex AcIdInQueryRegex = new(@"(?:^|[?&])ac_id=(?<id>\d+)(?:&|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex OnlineIpRegex = new(@"""online_ip""\s*:\s*""(?<ip>[^""]*)""", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ClientIpRegex = new(@"""client_ip""\s*:\s*""(?<ip>[^""]*)""", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HttpClient _http;
    private readonly HttpClient _insecureHttp;

    private enum PortalOnlineState
    {
        Unknown,
        Online,
        Offline
    }

    public NetworkProbeService()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };

        var insecureHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _insecureHttp = new HttpClient(insecureHandler) { Timeout = TimeSpan.FromSeconds(8) };
    }

    public async Task<string> GetProbeTextAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _http.GetStringAsync("http://www.msftconnecttest.com/connecttest.txt", cancellationToken);
        }
        catch
        {
            return string.Empty;
        }
    }

    public async Task<bool> IsHealthyAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        // Prefer querying campus gateway online state to avoid IPv6 partial-connect false positives.
        var portalState = await TryProbePortalOnlineStateAsync(settings, cancellationToken);
        if (portalState == PortalOnlineState.Online)
        {
            return true;
        }

        if (portalState == PortalOnlineState.Offline)
        {
            return false;
        }

        var probeText = await GetProbeTextAsync(cancellationToken);
        if (probeText.Contains("Microsoft Connect Test", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (LooksLikeCaptivePortal(probeText))
        {
            return false;
        }

        var context = ParsePortalContext(probeText, settings);
        if (context.IsWireless)
        {
            return false;
        }

        // Unknown state should not be treated as healthy; this avoids false "online" judgments.
        return false;
    }

    public async Task<PortalContext> ResolvePortalContextAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        var probeText = await GetProbeTextAsync(cancellationToken);
        return ParsePortalContext(probeText, settings);
    }

    public PortalContext ParsePortalContext(string probeText, AppSettings settings)
    {
        var context = new PortalContext
        {
            AcId = settings.AcId,
            PortalHost = settings.PortalHost,
            IsWireless = false
        };

        if (string.IsNullOrWhiteSpace(probeText) ||
            probeText.Contains("Microsoft Connect Test", StringComparison.OrdinalIgnoreCase))
        {
            return context;
        }

        var redirectMatch = RedirectRegex.Match(probeText);
        if (redirectMatch.Success)
        {
            var redirectUrl = redirectMatch.Groups["url"].Value;
            if (Uri.TryCreate(redirectUrl, UriKind.Absolute, out var uri))
            {
                context = new PortalContext
                {
                    PortalHost = uri.GetLeftPart(UriPartial.Authority),
                    AcId = ResolveAcIdFromUri(uri, settings.AcId),
                    IsWireless = IsWirelessMarker(probeText, uri.Query)
                };
            }
        }

        if (!context.IsWireless &&
            Regex.IsMatch(probeText, "wireless-v2-plain|wlanuserip=|NanHu_Wifi_|index_\\d+\\.html", RegexOptions.IgnoreCase))
        {
            context = new PortalContext
            {
                PortalHost = context.PortalHost,
                AcId = context.AcId,
                IsWireless = true
            };
        }

        return context;
    }

    private async Task<PortalOnlineState> TryProbePortalOnlineStateAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        foreach (var url in BuildRadUserInfoProbeUrls(settings.PortalHost))
        {
            try
            {
                using var response = await _insecureHttp.GetAsync(url, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                var state = ParsePortalOnlineState(body);
                if (state != PortalOnlineState.Unknown)
                {
                    return state;
                }
            }
            catch
            {
                // Try next candidate URL.
            }
        }

        return PortalOnlineState.Unknown;
    }

    private static IEnumerable<Uri> BuildRadUserInfoProbeUrls(string portalHost)
    {
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddCandidate(Uri baseUri)
        {
            var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var callback = $"cb_{ts}_{Random.Shared.Next(100000, 999999)}";
            var builder = new UriBuilder(baseUri)
            {
                Path = "/cgi-bin/rad_user_info",
                Query = $"callback={Uri.EscapeDataString(callback)}&_={ts}"
            };
            candidates.Add(builder.Uri.ToString());
        }

        if (TryNormalizePortalBaseUri(portalHost, out var normalized))
        {
            AddCandidate(normalized);

            var https = new UriBuilder(normalized) { Scheme = Uri.UriSchemeHttps, Port = 443 }.Uri;
            var http = new UriBuilder(normalized) { Scheme = Uri.UriSchemeHttp, Port = 80 }.Uri;
            AddCandidate(https);
            AddCandidate(http);
        }

        AddCandidate(new Uri("https://ipgw.neu.edu.cn/"));
        AddCandidate(new Uri("http://ipgw.neu.edu.cn/"));

        return candidates.Select(static u => new Uri(u));
    }

    private static bool TryNormalizePortalBaseUri(string input, out Uri uri)
    {
        var raw = (input ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            uri = default!;
            return false;
        }

        if (Uri.TryCreate(raw, UriKind.Absolute, out var absolute))
        {
            uri = absolute;
            return true;
        }

        if (Uri.TryCreate($"https://{raw.Trim('/')}", UriKind.Absolute, out var httpsUri) && httpsUri is not null)
        {
            uri = httpsUri;
            return true;
        }

        uri = default!;
        return false;
    }

    private static PortalOnlineState ParsePortalOnlineState(string text)
    {
        var raw = (text ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return PortalOnlineState.Unknown;
        }

        if (raw.Contains("not_online_error", StringComparison.OrdinalIgnoreCase))
        {
            return PortalOnlineState.Offline;
        }

        if (raw.Contains(@"""error"":""ok""", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains(@"""res"":""ok""", StringComparison.OrdinalIgnoreCase))
        {
            return PortalOnlineState.Online;
        }

        // CSV format: username,...,online_ip,...
        var csvParts = raw.Split(',');
        if (csvParts.Length >= 9 && !string.IsNullOrWhiteSpace(csvParts[0]) && IsLikelyIPv4(csvParts[8]))
        {
            return PortalOnlineState.Online;
        }

        var onlineIp = FirstMatch(OnlineIpRegex, raw, "ip");
        var clientIp = FirstMatch(ClientIpRegex, raw, "ip");
        if (IsLikelyIPv4(onlineIp) || IsLikelyIPv4(clientIp))
        {
            return PortalOnlineState.Online;
        }

        return PortalOnlineState.Unknown;
    }

    private static string FirstMatch(Regex regex, string input, string groupName)
    {
        var match = regex.Match(input);
        return match.Success ? match.Groups[groupName].Value.Trim() : string.Empty;
    }

    private static bool IsLikelyIPv4(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return System.Net.IPAddress.TryParse(value.Trim(), out var ip) &&
               ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    }

    private static bool LooksLikeCaptivePortal(string probeText)
    {
        if (string.IsNullOrWhiteSpace(probeText))
        {
            return false;
        }

        return RedirectRegex.IsMatch(probeText)
               || probeText.Contains("srun_portal", StringComparison.OrdinalIgnoreCase)
               || probeText.Contains("ipgw.neu.edu.cn", StringComparison.OrdinalIgnoreCase)
               || probeText.Contains("index_", StringComparison.OrdinalIgnoreCase)
               || probeText.Contains("ac_id=", StringComparison.OrdinalIgnoreCase)
               || probeText.Contains("wlanuserip=", StringComparison.OrdinalIgnoreCase);
    }

    private static int ResolveAcIdFromUri(Uri uri, int defaultValue)
    {
        var queryWithPrefix = uri.Query.StartsWith("?", StringComparison.Ordinal) ? uri.Query : "?" + uri.Query;
        var queryMatch = AcIdInQueryRegex.Match(queryWithPrefix);
        if (queryMatch.Success && int.TryParse(queryMatch.Groups["id"].Value, out var fromQuery))
        {
            return fromQuery;
        }

        return ResolveAcIdFromPath(uri.AbsolutePath, defaultValue);
    }

    private static int ResolveAcIdFromPath(string absolutePath, int defaultValue)
    {
        var match = AcIdRegex.Match(absolutePath);
        if (match.Success && int.TryParse(match.Groups["id"].Value, out var parsed))
        {
            return parsed;
        }

        return defaultValue;
    }

    private static bool IsWirelessMarker(string probeText, string query)
    {
        return query.Contains("wlanuserip=", StringComparison.OrdinalIgnoreCase)
               || probeText.Contains("wireless-v2-plain", StringComparison.OrdinalIgnoreCase);
    }
}
