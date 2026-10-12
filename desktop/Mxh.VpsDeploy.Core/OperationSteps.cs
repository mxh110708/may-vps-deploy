using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public static class OperationSteps
{
    public static bool HasDeploymentProgress(OperationKind kind) => kind is OperationKind.Deploy or OperationKind.Resume or OperationKind.InstallComponent or OperationKind.MeasureNetwork or OperationKind.TuneNetwork or OperationKind.BbrKernel or OperationKind.CheckComponentUpdate;
    public static IReadOnlyList<PlannedTaskStep> Create(OperationRequest request, JsonObject plan)
    {
        var steps = new List<PlannedTaskStep>();
        if (request.Kind == OperationKind.CheckComponentUpdate) return [new("component-release-check", "查询并核对官方稳定版", "锁定具体发行资产与摘要，只查询版本，不安装软件。")];
        void Add(string id, string title, string description) => steps.Add(new(id, title, description));
        if (request.Kind == OperationKind.BbrKernel)
        {
            var action = request.Options.Text("Action");
            if (action is "Check" or "Install") Add("kernel-check", "检查 BBR 与内核兼容性", "只读核对运行版本、GRUB、驱动和可用空间。");
            if (action == "Install") Add("kernel-install", "安装受管 BBR v3 内核", "核验已审阅版本的签名与包哈希，在 VPS 独立任务中安装；旧内核继续运行。");
            if (action is "Activate" or "Rollback" or "RollbackOriginal" or "Reconcile") Add("kernel-state", "核对原内核事务", "确认受管身份，沿用已有结果，不重放命令。");
            if (action == "Activate") Add("kernel-reboot", "重启到新内核", "使用单次启动项，保留旧内核为验收前的默认项。");
            if (action is "Activate" or "Reconcile") Add("kernel-accept", "验收并提交", "核验 BBR v3、原服务及管理连接，确认后才设为默认。");
            if (action is "Rollback" or "RollbackOriginal") Add("kernel-rollback", action == "RollbackOriginal" ? "回到 VPS 原有内核" : "回退上一内核", "只恢复受管启动设置，必要时重启并核对管理连接。");
            return steps;
        }
        if (request.Kind == OperationKind.MeasureNetwork)
        {
            Add("network-connection", "核对管理连接", "使用已归档的连接读取 VPS。");
            Add("network-measurement", "测量实际入口线路", "采集资源、实际 TCP RTT、吞吐、响应延迟及有限 UDP 样本；不修改网络参数。");
            Add("network-analysis", "生成并保存建议", "结合套餐、内存与时段生成建议，明确未覆盖的条件。"); return steps;
        }
        if (request.Kind == OperationKind.TuneNetwork)
        {
            Add("network-preflight", "核对配置与队列", "确认当前用途、参数、管理入口和可恢复的队列布局。");
            Add("network-backup", "保存网络恢复点", "保存运行值、实际队列及受管文件，启用限时回滚保护。");
            Add("network-apply", "应用并核验参数", "启用 fq 和可用 BBR；检查实际队列与管理连接。");
            if (request.Options.Text("Profile") == "EntryMeasured") Add("network-retest", "复测同一条线路", "对比吞吐和传输中延迟，检查实际收益。");
            Add("network-completion", "确认结果或恢复", request.Options.Text("Profile") == "EntryMeasured"
                ? "复测没有明确收益则恢复原值；保留记录与恢复材料。"
                : "确认实际队列、拥塞控制与管理连接；保留记录与恢复材料。"); return steps;
        }
        if (request.Kind == OperationKind.InstallComponent)
        {
            var selected = ComponentInstallations.Selected(request.Options);
            Add("installation-preflight", "核对现有实例与端口", "核对管理连接、现有服务和归档；确认本次组件尚未安装、端口未占用。");
            Add("installation-backup", "建立组件恢复快照", "只备份本次操作范围，并启用限时回滚保护。");
            foreach (var component in selected)
            {
                string Step(string stage) => ComponentInstallations.StepId(request.Options, stage, component);
                if (component == "RealityEntry") Add(Step("target-audit"), "审计 Reality 目标", "验证目标的 TLS 与连接质量。");
                if (component == "AnyTlsEntry") Add(Step("certbot-dns"), "申请 AnyTLS 可信证书", "使用 DNS 验证申请证书，并设置续期。");
                Add(Step("component-install"), "安装 " + ComponentInstallations.Label(component), component == "Tunnel" ? "安装连接器并验证 Cloudflare 连接；公开路由随后配置与验证。" : "安装固定版本及本次组件配置。");
            }
            if (selected.Any(DeploymentPlans.Roles[..3].Contains)) Add("installation-firewall", "更新协议放行规则", "受管防火墙一次补充本轮新协议端口，保留已有规则。");
            Add("installation-validation", "验收新增组件", "检查服务、连接及既有组件是否保留。");
            Add("installation-archive", "更新同一实例归档", "归档新增组件及验收结果。");
            Add("installation-commit", "确认完成", "提交组件事务，解除限时回滚保护。");
            return steps;
        }
        if (!HasDeploymentProgress(request.Kind)) return steps;
        Add("audit", "系统审计", "确认目标系统及新机条件。");
        Add("management-key", "准备管理密钥", "准备本地密钥和访问权限。");
        Add("deployment-baseline", "备份部署前基线", "保留受管文件和管理入口的恢复材料。");
        Add("bootstrap-access", "建立密钥访问", "安装并验证管理公钥。");
        Add("base-system", "准备系统与管理用户", "安装基础依赖，建立管理账户。");
        Add("ssh-transition", "验证主、救援 SSH", "确认两个管理入口可登录。");
        if (DeploymentPlans.Uses(plan, "RealityEntry") && plan.Text("Reality.TargetMode") != "LocalOwnedTls") Add("target-audit", "审计 Reality 目标", "验证目标 TLS 和连接质量。");
        if (plan.Flag("TrustedTls.Enabled")) Add("certbot-dns", "申请可信证书", "执行 DNS 验证并设置续期。");
        if (DeploymentPlans.Uses(plan, "RealityEntry") && plan.Text("Reality.TargetMode") == "LocalOwnedTls") Add("local-https-target", "配置本机 HTTPS 目标", "配置 Reality 使用的本机 TLS 目标。");
        foreach (var role in DeploymentPlans.Roles[..3].Where(role => DeploymentPlans.Uses(plan, role))) Add(plan["Roles"] == null ? "protocol-install" : "protocol-install-" + role, "安装 " + ComponentInstallations.Label(role), "生成协议配置并验证监听。");
        if (DeploymentPlans.Purposes(plan).Count(role => role != "MonitorOnly") > 1) Add("protocol-selection", "启用所选协议", "按计划选择入口与落地的启用状态。");
        Add("nftables-transition", "配置受管防火墙", "放行管理入口和所选协议。");
        if (plan.Flag("Komari.Enabled")) Add("komari-agent", "安装 Komari Agent", "连接到所填主控并启用指标上报。");
        Add("final-validation", "独立验收", "检查管理入口、服务与客户端真实连接。");
        Add("ssh-cutover", "完成管理入口切换", "确认关闭初始入口并复核防火墙。");
        Add("private-archive", "保存私有归档", "归档配置、凭据和验收结果。");
        Add("deployment-commit", "确认部署完成", "提交部署基线，记录最终结果。");
        return steps;
    }
}
