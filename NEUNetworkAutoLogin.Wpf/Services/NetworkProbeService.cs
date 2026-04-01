using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class NetworkProbeService
{
    private static readonly Regex RedirectRegex = new(@"location\.href=['""](?<url>[^'""]+)['""]", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex AcIdRegex = new(@"index_(?<id>\d+)\.html", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly HttpClient _http;
    private readonly HttpClient _insecureHttp;

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
        var probeText = await GetProbeTextAsync(cancellationToken);
        if (probeText.Contains("Microsoft Connect Test", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var context = ParsePortalContext(probeText, settings);
        if (context.IsWireless)
        {
            return false;
        }

        try
        {
            using var response = await _insecureHttp.GetAsync("https://www.baidu.com", cancellationToken);
            return response.StatusCode == HttpStatusCode.OK;
        }
        catch
        {
            return false;
        }
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
                    AcId = ResolveAcIdFromPath(uri.AbsolutePath, settings.AcId),
                    IsWireless = IsWirelessMarker(probeText, uri.Query)
                };
            }
        }

        if (!context.IsWireless && Regex.IsMatch(probeText, "wireless-v2-plain|wlanuserip=|NanHu_Wifi_|index_\\d+\\.html", RegexOptions.IgnoreCase))
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
