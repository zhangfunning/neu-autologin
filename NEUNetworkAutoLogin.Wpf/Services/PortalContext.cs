namespace NEUNetworkAutoLogin.Services;

public sealed class PortalContext
{
    public bool IsWireless { get; init; }
    public string PortalHost { get; init; } = "https://ipgw.neu.edu.cn/";
    public int AcId { get; init; } = 16;
}
