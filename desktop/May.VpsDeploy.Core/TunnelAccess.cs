using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class TunnelAccess
{
    public static string NormalizeUrl(string value)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var url) || url.Scheme != "https" || url.HostNameType != UriHostNameType.Dns || url.IsLoopback || url.Port != 443 || url.AbsolutePath != "/" || url.UserInfo != "" || url.Query != "" || url.Fragment != "")
            throw new OperationException("请填写公开主控的完整 HTTPS 网址，使用根路径，不包含账号、查询参数或片段。", code: "TunnelPublicUrlInvalid");
        return url.GetLeftPart(UriPartial.Authority);
    }
    public static string ServiceUrl(JsonObject plan) => plan.Number("KomariController.Port") is > 0 and <= 65535 ? "http://127.0.0.1:" + plan.Number("KomariController.Port") : "尚未安装本机主控";
    public static string Failure(string code, int httpStatus = 0) => code switch
    {
        "TunnelNotConnected" => "Tunnel 连接器尚未就绪。先检查连接 Token 和连接器状态，再配置公开路由。",
        "ControllerUnavailable" => "本机主控接口不可访问。先安装或检查本机主控及其 HTTP 端口。",
        "DnsFailure" => "公开主机名无法解析。核对 Cloudflare 的已发布应用程序路由及主机名。",
        "TlsFailure" => "公开网址的 TLS 证书验证失败。核对主机名和 Cloudflare 证书状态。",
        "HttpRejected" => (httpStatus is >= 100 and <= 599 ? "公开接口返回 HTTP " + httpStatus + "。" : "公开接口未返回成功响应。") + "核对服务 URL、Tunnel 状态与 Cloudflare Access 规则。",
        "Timeout" => "公开访问检查超时。核对路由是否已生效，再重新检查。",
        "VersionMismatch" => "公开接口与本机主控的版本不同。核对路由是否指向这台 VPS 的主控服务。",
        _ => "公开网址返回的内容不是可识别的 Komari 接口。核对路由主机名、服务 URL 和 Access 规则。"
    };
}

public sealed partial class WorkflowEngine
{
    private async Task VerifyTunnelAccess(Context c)
    {
        OperationPolicy.Validate(c.Request);
        var url = TunnelAccess.NormalizeUrl(c.Request.Options.Text("PublicUrl"));
        var targets = MaintenanceTargets.Monitoring(c.Plan, c.State);
        if (!targets.Where(t => t.Scope is "Tunnel" or "KomariController").All(t => t.Installed) || c.Plan.Number("KomariController.Port") is < 1 or > 65535)
            throw new OperationException("先安装并核对 Tunnel 连接器与本机主控，再配置和验证公开访问。", code: "TunnelAccessNotReady");
        c.Report("tunnel-public-access", "正在核对连接器、本机主控与公开 HTTPS 接口。");
        var result = await c.Run("tunnel-public-audit.sh", new() { ["PUBLIC_URL"] = url, ["CONTROLLER_PORT"] = c.Plan.Text("KomariController.Port"), ["METRICS_PORT"] = c.Plan.Text("Cloudflared.MetricsPort", "20241") }, timeout: 90, marker: "TUNNEL_ACCESS_OK");
        var evidence = JsonNode.Parse(RemoteAssets.Marker(result.Output, "TUNNEL_ACCESS"))!.AsObject();
        var passed = evidence.Flag("Passed") && evidence.Flag("ConnectorReady") && evidence.Text("LocalVersion") != "" && evidence.Text("PublicVersion") == evidence.Text("LocalVersion");
        if (!passed && evidence.Text("Code") == "") evidence["Code"] = "EvidenceIncomplete";
        c.State["TunnelAccess"] = new JsonObject { ["Status"] = passed ? "Passed" : "Failed", ["PublicUrl"] = url, ["At"] = DateTimeOffset.UtcNow, ["Code"] = evidence.Text("Code"), ["Evidence"] = evidence };
        if (passed) c.Plan.Put("Cloudflared.PublicUrl", JsonValue.Create(url));
        c.Save();
        if (!passed) throw new OperationException(TunnelAccess.Failure(evidence.Text("Code"), evidence.Number("HttpStatus")), code: "TunnelPublic" + evidence.Text("Code"), nextAction: "在实例页按公开访问指引核对路由，再点击验证公开访问；无需重新安装连接器。");
        c.Report("公开访问已验证", "连接器就绪，公开 HTTPS 接口可访问且版本与本机主控一致。检查结果已保存。");
    }
}
