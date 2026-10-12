using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed record ReviewItem(string Label, string Value);
public sealed record ReviewSection(string Title, IReadOnlyList<ReviewItem> Items);

public static class DeploymentReview
{
    public static string Purpose(string role) => role switch { "RealityEntry" => "Reality 入口", "AnyTlsEntry" => "AnyTLS / ECH 入口", "ShadowsocksLanding" => "Shadowsocks 落地", _ => "基础维护" };
    public static IReadOnlyList<ReviewSection> Sections(JsonObject plan, OperationKind kind, JsonObject? state = null)
    {
        var import = kind is OperationKind.ConnectExisting or OperationKind.ResumeImport;
        var sections = new List<ReviewSection>
        {
            new("部署对象", [new("服务商 / 实例", plan.Text("Provider") + " / " + plan.Text("Instance")), new("节点名称", plan.Text("NodeName")), new("IPv4", plan.Text("Server.IPv4")), new("IPv6", plan.Text("Server.IPv6", "未填写") is "" ? "未填写" : plan.Text("Server.IPv6")), new("任务", import ? "只读接入已有 VPS" : kind == OperationKind.Resume ? "继续已保存的部署草稿" : "部署新 VPS"), new("系统要求", "Debian 12/13 amd64 · 执行时审计，尚未检查")]),
            new("SSH 连接与管理", [new("当前连接", "root · 端口 " + (state?.Text("CurrentManagementPort", plan.Text("Server.BootstrapSshPort")) ?? plan.Text("Server.BootstrapSshPort"))), new("本次认证", plan.Text("Server.BootstrapAuth") == "ExistingKey" ? "所选私钥，口令在需要时输入" : "执行时输入 SSH 密码"), new("部署后主入口", import ? "保留现有 SSH 配置" : plan.Text("Ports.SshPrimary")), new("部署后备用入口", import ? "接入时只读识别" : plan.Text("Ports.SshRescue")), new("管理凭据", import ? "保留现有认证方式" : "建立应用管理密钥和 admin 账号；原始私钥保留"), new("入口切换", import ? "不修改 SSH" : "验证两个管理入口后，按流程确认初始入口切换")])
        };
        if (import)
            sections.Add(new("读取范围", [new("配置", "识别受支持的协议、SSH 和监控配置"), new("服务器改动", "不安装组件，不切换认证或修改防火墙"), new("不支持的布局", "停止并说明原因") ]));
        else
        {
            if (plan["InstallationVersions"] is JsonObject selection) sections.Add(new("本轮安装版本", [new("来源", selection.Text("Source") == "Latest" ? "官方最新稳定版（查询时）" : "应用固定版本"), new("程序与校验", InstallationVersions.Summary(selection, InstallationVersions.DeploymentComponents(plan)))]));
            sections.Add(new("用途与默认状态", [new("用途组合", string.Join(" + ", DeploymentPlans.Purposes(plan).Select(Purpose))), new("默认入口", plan.Text("ActiveEntry") == "" ? "无代理入口" : Purpose(plan.Text("ActiveEntry"))), new("多入口", DeploymentPlans.Purposes(plan).Count(r => r is "RealityEntry" or "AnyTlsEntry") > 1 ? "两个入口均安装，默认只启用所选入口" : "按所选用途安装") ]));
            if (DeploymentPlans.Uses(plan, "RealityEntry")) sections.Add(new("Reality", [new("核心", "Xray " + plan.Text("Reality.XrayVersion") + (plan.Text("Reality.XrayVersionChannel") == "OfficialStable" ? " · 官方稳定版" : " · 固定已验证版本")), new("主端口", plan.Text("Ports.XrayPrimary")), new("备用端口", plan.Number("Ports.XrayBackup") == 0 ? "关闭" : plan.Text("Ports.XrayBackup")), new("目标 / SNI", plan.Text("Reality.ServerName")), new("目标方式", plan.Text("Reality.TargetMode") == "LocalOwnedTls" ? "自己的域名与本机 HTTPS" : "外部目标 · 执行时审计，尚未验收"), new("出口", plan.Flag("Reality.ForceIpv4Egress") ? "IPv4" : "按协议配置") ]));
            if (DeploymentPlans.Uses(plan, "AnyTlsEntry")) sections.Add(new("AnyTLS / ECH", [new("核心", "sing-box " + plan.Text("AnyTls.SingBoxVersion")), new("端口", plan.Text("Ports.AnyTlsPrimary")), new("服务器名称", plan.Text("AnyTls.ServerName")), new("ECH public name", plan.Text("AnyTls.EchPublicName")), new("出口", plan.Flag("AnyTls.ForceIpv4Egress") ? "IPv4" : "按协议配置"), new("Padding", "官方默认") ]));
            if (DeploymentPlans.Uses(plan, "ShadowsocksLanding")) sections.Add(new("Shadowsocks 落地", [new("核心", "sing-box " + plan.Text("Shadowsocks.SingBoxVersion")), new("端口", plan.Text("Ports.LandingShadowsocks") + " · TCP / UDP"), new("方法", plan.Text("Shadowsocks.Method")), new("可信入口", (plan.Strings("Shadowsocks.TrustedEntryIPv4s").Length + plan.Strings("Shadowsocks.TrustedEntryIPv6s").Length) + " 个地址"), new("第二用户", plan.Flag("Shadowsocks.SecondaryIpv6Enabled") ? "启用 · 专用 IPv6 出口" : "未启用") ]));
            sections.Add(new("附加组件与改动", [new("防火墙", plan.Text("Firewall.Mode") == "PreserveExisting" ? "保留现有配置" : "配置部署器管理的 nftables 规则"), new("证书", plan.Flag("TrustedTls.Enabled") ? "申请所选协议的域名证书；Token 只从私人文件读取" : "未启用"), new("Komari Agent", plan.Flag("Komari.Enabled") ? "安装 " + plan.Text("Komari.AgentVersion") + " · Token 在执行时输入" : "未启用"), new("监控主控", plan.Flag("Komari.Enabled") ? PublicUrl(plan.Text("Komari.Endpoint")) : "无需填写"), new("网络调优", "本次不执行 · 部署完成后在独立页面手动选择") ]));
            sections.Add(new("执行与失败处理", [new("执行顺序", "系统审计 → 部署基线备份 → 管理访问 → 系统与所选协议 → 防火墙 → 验收 → 提交归档"), new("首次身份确认", "独立核对服务器指纹，再建立正式 SSH 连接"), new("连接 / 审计失败", "保留部署草稿，显示具体原因，可继续或删除"), new("未确认写入", "保留事务与基线；先核对状态，再按范围恢复") ]));
        }
        sections.Add(new("本地归档与验收", [new("实例目录", plan.Text("Paths.Archive")), new("私人材料", "凭据加密保存；密钥、配置和实例备份存入该实例目录"), new("独立验收", import ? "读取结果与归档一致性；运行状态需另做健康检查" : "管理 SSH、服务监听、配置与实际协议连接分别检查"), new("当前状态", "这是待执行计划，不代表已连接或已检查通过") ]));
        return sections;
    }
    private static string PublicUrl(string text)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var value) || value.Scheme is not ("https" or "http")) return "地址待核对";
        return new UriBuilder(value) { UserName = "", Password = "", Query = "", Fragment = "" }.Uri.GetLeftPart(UriPartial.Path);
    }
}
