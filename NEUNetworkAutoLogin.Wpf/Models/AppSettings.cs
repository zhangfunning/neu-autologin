namespace NEUNetworkAutoLogin.Models;

public sealed class AppSettings
{
    public int AcId { get; set; } = 16;
    public string PortalHost { get; set; } = "https://ipgw.neu.edu.cn/";
    public string ServiceBaseUrl { get; set; } = "https://ipgw.neu.edu.cn/srun_portal_sso";

    public int InitialDelaySeconds { get; set; } = 20;
    public int RetryDelaySeconds { get; set; } = 15;
    public int MaxAttempts { get; set; } = 8;
    public int MonitorIntervalSeconds { get; set; } = 60;
    public int FailureCooldownMinutes { get; set; } = 10;
    public int HealthCheckTimeoutSeconds { get; set; } = 8;
}
