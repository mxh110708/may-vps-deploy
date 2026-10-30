using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class OperationSteps
{
    public static bool HasDeploymentProgress(OperationKind kind) => kind is OperationKind.Deploy or OperationKind.Resume or OperationKind.InstallComponent or OperationKind.MeasureNetwork or OperationKind.TuneNetwork or OperationKind.BbrKernel or OperationKind.CheckComponentUpdate or OperationKind.ServerOutbound or OperationKind.TcpForward or OperationKind.UdpForward or OperationKind.MayMonitor or OperationKind.TcpChain or OperationKind.Inbounds or OperationKind.WireGuardTunnel;
    public static IReadOnlyList<PlannedTaskStep> Create(OperationRequest request, JsonObject plan)
    {
        var steps = new List<PlannedTaskStep>();
        if (request.Kind == OperationKind.CheckComponentUpdate) return [new("component-release-check", "查询并核对官方稳定版", "锁定具体发行资产与摘要，只查询版本，不安装软件。")];
        void Add(string id, string title, string description) => steps.Add(new(id, title, description));
        if (request.Kind == OperationKind.Inbounds)
        {
            Add("inbound-preflight", "核对资源引用与实际布局", "核对管理连接、用户/证书/出站引用、端口和明确影响范围。");
            if (request.Options.Text("Action") != "Check") { Add("inbound-backup", "建立入站范围恢复点", "仅保存受影响入站及本次防火墙，启用限时回退。"); Add("inbound-apply", "应用独立入站配置", "验证固定核心配置后，仅重启本次影响的入站。"); }
            Add("inbound-validation", "验收入站用户与真实代理", "按用户、监听地址族完成实际代理 HTTPS 请求。");
            if (request.Options.Text("Action") != "Check") Add("inbound-commit", "提交并保存资源目录", "确认同一事务并更新当前入站及验证记录。"); return steps;
        }
        if (request.Kind == OperationKind.WireGuardTunnel)
        {
            if (request.Options.Text("Action") == "Recover") { Add("wg-recovery", "协调恢复两端隧道", "核对原任务和恢复点，补偿已提交参与实例。"); return steps; }
            Add("wg-preflight", "核对两台实例", "核对独立身份、管理连接、端口、地址与实际资源。");
            if (request.Options.Text("Action") != "Check") { Add("wg-backup", "建立两端恢复点", "只保存隧道与本次涉及的受管防火墙。"); Add("wg-apply", "应用 WireGuard 通道", "两端生成私钥、交换公钥并建立内核通道；或移除本通道。"); }
            Add("wg-validation", "双向 TCP 与 UDP 验收", "随机挑战、正确隧道路由、鉴权、配置与管理连接均须匹配。");
            if (request.Options.Text("Action") != "Check") Add("wg-commit", "提交两端隧道", "逐台提交，确认丢失先对账，不重放变更。"); return steps;
        }
        if (request.Kind == OperationKind.TcpChain)
        {
            if (request.Options.Text("Action") == "Recover") { Add("chain-recovery", "协调恢复整条线路", "按原任务身份恢复前置与中转，核对原资源和管理连接。"); return steps; }
            Add("chain-preflight", "核对三台依赖与端口", "核对实际机器身份、管理连接、配置摘要、端口及来源限制。");
            if (request.Options.Text("Action") != "Check")
            {
                Add("chain-backup", "建立两台恢复点", "分别保存本次转发与必要的受管防火墙，启用限时回退。");
                Add("chain-apply", request.Options.Text("Action") == "Remove" ? "从前向后移除线路" : "从后向前应用线路", "逐台核对实际规则；保留其他转发及落地代理。");
            }
            Add("chain-validation", "验收实际线路与既有规则", "分段 TCP 与整链代理 HTTPS 分别核验，再核对资源和管理连接。");
            if (request.Options.Text("Action") != "Check") Add("chain-commit", "协调提交与归档", "逐台提交后同步依赖；部分提交失败时按本次快照补偿。");
            return steps;
        }
        if (request.Kind == OperationKind.MayMonitor)
        {
            Add("may-preflight", "核对 May 组件归属", "核对系统、SSH、固定版本、实际文件及服务身份。");
            if (request.Options.Text("Action") == "Check") return steps;
            Add("may-backup", "保存组件一致性备份", "短暂停止所选 May 服务，保存程序、配置和数据，启用限时回退保护。");
            if (request.Options.Text("Action") != "Backup") Add("may-apply", "应用本次 May 操作", "只处理明确选择的 May 组件，保留旧监控及其他服务。");
            Add("may-verify", "核对组件与管理连接", "确认实际归属、服务及管理连接；外部 HTTPS 和业务指标在监测页另行核验。");
            Add("may-commit", "确认事务完成", "记录范围、摘要与恢复点，解除本次回退计时器。");
            return steps;
        }
        if (request.Kind is OperationKind.TcpForward or OperationKind.UdpForward)
        {
            var udp = request.Kind == OperationKind.UdpForward; var prefix = udp ? "udp-forward-" : "forward-";
            Add(prefix + "preflight", "核对转发、端口与管理连接", "只读检查实际归属、白名单、可用程序和监听冲突。");
            if (request.Options.Text("Action") != "Check")
            {
                Add(prefix + "backup", "建立独立转发恢复点", "仅保存转发及本次涉及的受管防火墙，启用限时回滚。");
                Add(prefix + "apply", udp ? "应用 UDP 转发" : "应用 TCP 转发", "更新本组件监听与白名单，不重启代理或监控。");
            }
            Add(prefix + "validation", "核验实际转发", udp ? "从控制端经 UDP 转发取得匹配的 DNS 回答或原样回显。" : "从控制端经转发执行 TLS、SSH 响应或代理 HTTPS 验收。");
            if (request.Options.Text("Action") != "Check") Add(prefix + "commit", "确认完成", "核对事务身份并解除限时回滚。");
            return steps;
        }
        if (request.Kind == OperationKind.ServerOutbound)
        {
            var target = ServerOutboundRouting.Label(request.Options.Text("Protocol"));
            Add("outbound-preflight", "核对入站与实际配置", "核对管理连接、运行中的 " + target + " 服务和审阅时的配置摘要。");
            Add("outbound-backup", "建立组件恢复点", "只备份 " + target + "，启用限时回滚保护。");
            Add("outbound-apply", "应用固定下一跳", "校验实际核心支持后，只替换 " + target + " 配置并重启此服务。");
            Add("outbound-validation", "核验实际代理出口", "独立检查 HTTPS、预期出口地址和 UDP；未完成不提交。");
            Add("outbound-archive", "归档配置与验收", "保留下一跳身份及本次验证证据。");
            Add("outbound-commit", "确认完成", "核对事务身份并解除限时回滚保护。"); return steps;
        }
        if (request.Kind == OperationKind.BbrKernel)
        {
            var action = request.Options.Text("Action");
            if (action is "Check" or "Install") Add("kernel-check", "检查 BBR 与内核兼容性", "只读核对运行版本、GRUB、驱动和可用空间。");
            if (action == "Install") Add("kernel-install", "安装 Google BBR v3 内核", "上传并校验随应用提供的固定预编译包，只安装单个镜像，旧内核继续运行。");
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
