namespace NEUNetworkAutoLogin.Services;

public sealed class PortalLoginResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string FinalUrl { get; init; } = string.Empty;
    public IReadOnlyList<string> Trace { get; init; } = Array.Empty<string>();
}
