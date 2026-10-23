using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public interface IOperationWorkflow
{
    Task<TaskOutcome> ExecuteAsync(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellationToken);
}

public sealed class TaskCoordinator(ArchiveStore store, IOperationWorkflow workflow)
{
    private readonly SemaphoreSlim active = new(1, 1);
    public TaskRecord? Current { get; private set; }
    public ReviewedOperation Review(OperationRequest request)
    {
        var snapshot = request.Snapshot(); OperationPolicy.Validate(snapshot);
        var planHash = ArchiveFingerprint(snapshot);
        JsonObject? kernelCatalog = null;
        if (snapshot.Kind == OperationKind.BbrKernel && snapshot.Options.Text("Action") == "Install")
        {
            kernelCatalog = BbrKernels.Catalog(store.Paths);
            if (kernelCatalog.Text("Id") != snapshot.Options.Text("CatalogId") || kernelCatalog.Text("Sha256") != snapshot.Options.Text("CatalogSha256") || kernelCatalog.Text("Commit") != snapshot.Options.Text("SourceCommit")) throw new OperationException("源码候选与待审阅目标不一致，请重新选择版本。");
        }
        var summary = snapshot.Kind == OperationKind.UdpForward ? UdpForwarding.Prepare(store, snapshot).Summary : snapshot.Kind == OperationKind.TcpForward ? TcpForwarding.Prepare(store, snapshot).Summary : snapshot.Kind == OperationKind.ServerOutbound ? ServerOutboundRouting.Prepare(store, snapshot).Summary : OperationPolicy.Summary(snapshot, kernelCatalog);
        return new(snapshot, Fingerprint(snapshot), planHash, summary);
    }
    public static string Fingerprint(OperationRequest request) => ArchiveStore.Fingerprint(new JsonObject
    {
        ["kind"] = request.Kind.ToString(), ["instance"] = request.InstanceRelativePath, ["options"] = request.Options.DeepClone()
    });
    private string ArchiveFingerprint(OperationRequest request)
    {
        var directory = store.Paths.Instance(request.InstanceRelativePath); var files = new JsonObject();
        foreach (var name in new[] { "deployment-plan.json", "deployment-state.json", "secrets.dotnet.private.json", "deployment-secrets.private.json", "operation-pending.dotnet.json" })
        { var path = SafePath.Resolve(directory, name); files[name] = ClientSchemes.SourceFingerprint(path); }
        if (request.Kind == OperationKind.TuneNetwork && request.Options.Text("Profile") == "EntryMeasured")
        {
            var id = NetworkTuning.Id(request.Options.Text("MeasurementId")); files["Measurement"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "network-measurements/" + id + ".json"));
            var measurement = NetworkTuning.ReadReport(directory, id); files["NetworkPeer"] = NetworkTuning.PeerArchiveFingerprint(store, measurement["Options"]!.AsObject());
        }
        if (request.Kind == OperationKind.MeasureNetwork) files["NetworkPeer"] = NetworkTuning.PeerArchiveFingerprint(store, request.Options);
        if (request.Kind == OperationKind.TcpForward)
        {
            foreach (var asset in new[] { "scripts/forwarding-host.py", "scripts/tcp-forwarding.py", "assets/remote/tcp-forward-read.sh", "assets/remote/tcp-forward-apply.sh", "assets/remote/protocol-migration-arm-rollback.sh", "assets/remote/firewall-tools.sh" }) files[asset] = ClientSchemes.SourceFingerprint(store.Paths.Resolve(asset));
            foreach (var rule in TcpForwarding.Rules(request.Options["Configuration"] as JsonObject).Where(r => r.Flag("Enabled") && r.Text("Validation.Type") == "Proxy"))
                files["ForwardSource:" + rule.Text("Id")] = ClientSchemes.SourceFingerprint(ServerOutboundRouting.SchemeFile(store.Paths, rule.Text("Validation.SchemeId")));
        }
        if (request.Kind == OperationKind.UdpForward)
        {
            foreach (var asset in new[] { "scripts/forwarding-host.py", "scripts/udp-forwarding.py", "scripts/udp-forward-worker.py", "assets/remote/udp-forward-read.sh", "assets/remote/udp-forward-apply.sh", "assets/remote/protocol-migration-arm-rollback.sh", "assets/remote/nftables-apply.sh", "assets/remote/firewall-tools.sh" }) files[asset] = ClientSchemes.SourceFingerprint(store.Paths.Resolve(asset));
            foreach (var rule in UdpForwarding.Rules(request.Options["Configuration"] as JsonObject).Where(r => r.Flag("Enabled") && r.Text("Validation.Type") == "Shadowsocks"))
                files["UdpForwardSource:" + rule.Text("Id")] = ClientSchemes.SourceFingerprint(ServerOutboundRouting.SchemeFile(store.Paths, rule.Text("Validation.SchemeId")));
        }
        if (request.Kind == OperationKind.ServerOutbound)
        {
            files["ServerOutboundConfig"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative(request.Options.Text("Protocol"))));
            if (request.Options.Text("Action") == "Apply") files["ServerOutboundSource"] = ClientSchemes.SourceFingerprint(ServerOutboundRouting.SchemeFile(store.Paths, request.Options.Text("SchemeId")));
            foreach (var hop in ServerOutboundRouting.HopReferences(request.Options["AdditionalHops"]).OfType<JsonObject>()) files["ServerOutboundSource:" + hop.Text("Id")] = ClientSchemes.SourceFingerprint(ServerOutboundRouting.SchemeFile(store.Paths, hop.Text("SchemeId")));
            foreach (var asset in new[] { "server-outbound-read.sh", "server-outbound-apply.sh", "server-hop-probe.sh" }) files[asset] = ClientSchemes.SourceFingerprint(store.Paths.Resolve("assets/remote/" + asset));
        }
        if (request.Kind == OperationKind.BbrKernel)
        {
            foreach (var name in new[] { "config/kernel-catalog.json", "scripts/kernel-runtime.py", "scripts/kernel-engine.py", "scripts/bbr-runtime.py", "assets/kernel/commit.json", "assets/kernel/Makefile", "assets/kernel/tcp_bbr.c", "assets/remote/kernel-audit.sh", "assets/remote/kernel-prepare.sh", "assets/remote/kernel-status.sh", "assets/remote/kernel-boot.sh", "assets/remote/kernel-confirm.sh", "assets/remote/kernel-rollback.sh" }) files[name] = ClientSchemes.SourceFingerprint(store.Paths.Resolve(name));
            foreach (var name in new[] { "kernel.deb", "build-manifest.json", "kernel.config", "input.config" }) files["Prebuilt:" + name] = BbrKernels.FileDigest(store.Paths.Resolve("assets/kernel/" + name));
        }
        if (request.Kind == OperationKind.Upgrade || request.Kind == OperationKind.Komari && request.Options.Text("Action") == "Upgrade")
        {
            files["UpgradeVersions"] = ClientSchemes.SourceFingerprint(store.Paths.Resolve("config/versions.json"));
            files["UpgradeProgram"] = ClientSchemes.SourceFingerprint(store.Paths.Resolve(request.Kind == OperationKind.Upgrade ? "assets/remote/proxy-core-upgrade.sh" : "assets/remote/maintenance-komari.sh"));
            if (request.Options.Text("Source", "Fixed") == "Latest") files["ComponentRelease"] = ClientSchemes.SourceFingerprint(ComponentUpdates.CandidateFile(store.Paths, request.InstanceRelativePath, ComponentUpdates.Component(request)));
        }
        if (request.Kind is OperationKind.Deploy or OperationKind.Resume or OperationKind.InstallComponent)
        {
            foreach (var name in new[] { "config/versions.json", "scripts/component-releases.py", "assets/remote/xray-install.sh", "assets/remote/sing-box-install.sh", "assets/remote/sing-box-anytls-install.sh", "assets/remote/komari-agent.sh", "assets/remote/monitoring-component-install.sh" }) files["InstallationAsset:" + name] = ClientSchemes.SourceFingerprint(store.Paths.Resolve(name));
        }
        return ArchiveStore.Fingerprint(files);
    }
    public async Task<TaskRecord> ExecuteAsync(ReviewedOperation review, OperationRequest current, IProgress<TaskProgress> progress, CancellationToken cancellationToken)
    {
        if (Fingerprint(current) != review.Fingerprint || Fingerprint(review.Request) != review.Fingerprint) throw new OperationException("表单在审阅后发生变化，请重新审阅。");
        if (!await active.WaitAsync(0, cancellationToken)) throw new OperationException("已有任务执行中。");
        try
        {
            using var instanceLock = store.LockInstance(current.InstanceRelativePath);
            var planHash = ArchiveFingerprint(current);
            if (planHash != review.PlanFingerprint) throw new OperationException("实例归档在审阅后发生变化，请重新读取并审阅。");
            Current = new(Guid.NewGuid().ToString("N"), current.Kind, DateTimeOffset.UtcNow, null, TaskOutcome.Running, "准备", InstanceRelativePath: current.InstanceRelativePath, TargetLabel: OperationPolicy.TargetLabel(current));
            store.AppendHistory(Current);
            var reporting = new InlineProgress<TaskProgress>(p => { Current = Current with { Stage = p.Stage }; progress.Report(p); });
            try
            {
                var outcome = await workflow.ExecuteAsync(current.Snapshot(), Current.Id, reporting, cancellationToken);
                Current = Current with { Outcome = outcome, FinishedAt = DateTimeOffset.UtcNow };
            }
            catch (OperationCanceledException) { Current = Current with { Outcome = TaskOutcome.Cancelled, FinishedAt = DateTimeOffset.UtcNow }; }
            catch (Exception exception)
            {
                var safe = SafeFailures.Describe(exception);
                Current = Current with { Outcome = safe.NeedsRecovery ? TaskOutcome.NeedsRecovery : TaskOutcome.Failed,
                    SafeError = safe.Message, ErrorCode = safe.Code, NextAction = safe.NextAction, FinishedAt = DateTimeOffset.UtcNow };
            }
            store.AppendHistory(Current);
            return Current;
        }
        finally { active.Release(); }
    }
}

public sealed class InlineProgress<T>(Action<T> report) : IProgress<T> { public void Report(T value) => report(value); }

public static class OperationPolicy
{
    public static void Validate(OperationRequest request)
    {
        if (!Enum.IsDefined(request.Kind)) throw new OperationException("未知任务类型。");
        if (request.Kind == OperationKind.ServerOutbound) ServerOutboundRouting.ValidateOptions(request.Options);
        if (request.Kind == OperationKind.TcpForward) TcpForwarding.ValidateOptions(request.Options);
        if (request.Kind == OperationKind.UdpForward) UdpForwarding.ValidateOptions(request.Options);
        if (request.Kind == OperationKind.BbrKernel) BbrKernels.Validate(request.Options);
        if (request.Kind == OperationKind.CheckComponentUpdate) ComponentUpdates.ValidateQuery(request.Options);
        if (request.Kind == OperationKind.Upgrade || request.Kind == OperationKind.Komari && request.Options.Text("Action") == "Upgrade") ComponentUpdates.ValidateOptions(request);
        if (request.Kind == OperationKind.InstallComponent) ComponentInstallations.ValidateOptions(request.Options);
        if (request.Kind == OperationKind.TunnelAccess)
        {
            if (request.Options.Count != 1 || !request.Options.ContainsKey("PublicUrl")) throw new OperationException("公开访问检查只接受公开网址。");
            TunnelAccess.NormalizeUrl(request.Options.Text("PublicUrl"));
        }
        var names = request.InstanceRelativePath.Split('/');
        if (names.Length != 3 || names[2] != "May-VPS-Deploy" || names[0] != AppPaths.Segment(names[0]) || names[1] != AppPaths.Segment(names[1])) throw new OperationException("实例归档路径无效。");
        if (request.Kind == OperationKind.ProtocolState && request.Options.Text("Action") is not ("Enable" or "Disable" or "Switch" or "Uninstall")) throw new OperationException("未知协议操作。");
        if (request.Kind is OperationKind.Upgrade or OperationKind.Restore or OperationKind.Komari or OperationKind.Decommission)
        {
            if (!Enum.TryParse<ComponentScope>(request.Options.Text("Scope"), out var scope) || !Enum.IsDefined(scope)) throw new OperationException("请明确选择操作组件。");
            if (request.Kind == OperationKind.Restore && request.Options.Text("Backup") == "") throw new OperationException("请明确选择恢复归档。");
        }
        if (request.Kind == OperationKind.MeasureNetwork) NetworkTuning.ValidateMeasurement(request.Options);
        if (request.Kind == OperationKind.TuneNetwork)
        {
            var options = request.Options;
            if (options.Text("Scope") != "Network" || options.Text("Profile") is not ("LandingBasic" or "EntryBasic" or "EntryMeasured")) throw new OperationException("请选择有效的独立网络配置。");
            if (options.Any(p => !new[] { "Scope", "Profile", "MeasurementId", "MeasurementSha256", "BbrVersion" }.Contains(p.Key))) throw new OperationException("调优只接受由自动测量生成的建议；无需填写 RTT。");
            if (options.Text("BbrVersion", "Current") is not ("Current" or "v3")) throw new OperationException("请选择当前内核自带版本或 BBR v3。");
            if (options.Text("Profile") == "EntryMeasured")
            {
                NetworkTuning.Id(options.Text("MeasurementId"));
                if (!System.Text.RegularExpressions.Regex.IsMatch(options.Text("MeasurementSha256"), "^[a-f0-9]{64}$")) throw new OperationException("测量摘要无效，请重新生成建议。");
            }
            else if (options.ContainsKey("MeasurementId") || options.ContainsKey("MeasurementSha256")) throw new OperationException("基础配置无需指定测速记录。");
        }
        var scopeName = request.Options.Text("Scope", "Protocol");
        if (request.Kind == OperationKind.Upgrade && scopeName != "Protocol" || request.Kind == OperationKind.Restore && scopeName != "Protocol" || request.Kind == OperationKind.RotateCredentials && scopeName != "Protocol") throw new OperationException("任务与所选组件范围不匹配。监控组件请从对应的监控入口管理。");
        if (request.Kind == OperationKind.Komari && request.Options.ContainsKey("Protocol")) throw new OperationException("监控与访问操作不能混入代理协议。");
        if (request.Kind == OperationKind.Decommission && (scopeName != "ManagedInstance" || request.Options.Text("Action") is not ("Disable" or "RemoveManaged"))) throw new OperationException("请选择明确的实例退役范围。");
        if (request.Kind == OperationKind.Komari && !(scopeName switch { "KomariAgent" => request.Options.Text("Action") is "Upgrade" or "Remove", "KomariController" => request.Options.Text("Action") is "Upgrade" or "Backup" or "Restore", "Tunnel" => request.Options.Text("Action") is "Upgrade" or "RotateToken", _ => false })) throw new OperationException("该监控组件不支持所选操作。");
    }
    public static string TargetLabel(OperationRequest request) => request.Kind switch
    {
        OperationKind.TcpForward => "独立 TCP 端口转发",
        OperationKind.UdpForward => "独立 UDP 端口转发",
        OperationKind.ServerOutbound => ServerOutboundRouting.Label(request.Options.Text("Protocol")) + " · 服务器固定下一跳",
        OperationKind.CheckComponentUpdate => ComponentUpdates.Label(request.Options.Text("Component")) + " · 查询官方最新稳定版",
        OperationKind.InstallComponent => "追加安装 · " + ComponentInstallations.SelectionLabel(request.Options),
        OperationKind.TunnelAccess => "Cloudflare Tunnel · 公开访问验证",
        OperationKind.MeasureNetwork => "网络路径诊断 · " + NetworkTuning.DirectionLabel(request.Options),
        OperationKind.BbrKernel => BbrKernels.Label(request.Options.Text("Action")),
        OperationKind.TuneNetwork => request.Options.Text("Profile") == "LandingBasic" ? "落地机 · fq + BBR" : "入口机 · 网络调优",
        OperationKind.Upgrade => request.Options.Text("Protocol") switch { "RealityEntry" => "Xray · Reality 入口", "AnyTlsEntry" => "sing-box · AnyTLS / ECH 入口", "ShadowsocksLanding" => "sing-box · Shadowsocks 落地", _ => "代理核心" },
        OperationKind.Komari => (request.Options.Text("Scope") switch { "KomariAgent" => "Komari Agent", "KomariController" => "Komari 主控", _ => "Cloudflare Tunnel" }) + " · " + (request.Options.Text("Action") switch { "Upgrade" => "升级", "Remove" => "卸载", "Backup" => "一致性备份", "Restore" => "恢复备份", _ => "Token 轮换" }),
        _ => ""
    };
    public static string Summary(OperationRequest request, JsonObject? kernelCatalog = null) => request.Kind switch
    {
        OperationKind.CheckComponentUpdate => "经所选 VPS 查询 " + TargetLabel(request) + "。只读取官方稳定发行元数据，保存具体版本、资产身份和 SHA256；不会安装程序、重启服务或修改系统仓库。",
        OperationKind.ConnectExisting => "接入已有实例：只读识别现有配置，保留 SSH 认证、端口与防火墙。",
        OperationKind.ResumeImport => "继续接入草稿：重新只读识别现有配置，完成应用内归档。",
        OperationKind.Deploy => "新机部署：先审计系统与已有服务，建立备份后配置双 SSH 入口和所选用途；最后独立验收。网络调优由部署后另行手动发起。",
        OperationKind.HealthAudit => "只读健康与漂移检查；不重启或修改服务。",
        OperationKind.BbrKernel => "操作：" + TargetLabel(request) + "\n" + BbrKernels.SourceNotice + "\n" + (request.Options.Text("Action") switch
        {
            "Check" => "只读检查实际 BBR、系统、内存、磁盘、GRUB、驱动和随应用提供的固定内核；不会安装或重启，也不查询浮动版本。",
            "Install" => "来源：" + BbrKernels.PackageLabel + (kernelCatalog is null ? "" : "\n基础内核：" + kernelCatalog.Text("BaseKernel") + "\n本应用构建目标：" + kernelCatalog.Text("Kernel") + "\n官方提交日期：" + kernelCatalog.Text("SourceDate")) + "\n源码提交：" + request.Options.Text("SourceCommit") + "\n源码材料 SHA256：" + request.Options.Text("CatalogSha256") + BbrKernels.InstallDescription(kernelCatalog),
            "Activate" => "VPS 将重启，连接会暂时中断。单次启动新内核，重新核验 BBR v3、原服务及主/救援 SSH 后设为默认。新系统进入用户空间但 5 分钟未提交会回到旧内核；若无法启动用户空间，需要服务商控制台重启，下一次默认仍是旧内核。",
            "Rollback" => "只处理本轮受管内核启动设置，保留内核包。必要时重启到本轮升级前的上一内核，并重新核验管理连接；网络参数和应用服务配置保留。",
            "RollbackOriginal" => "核对最初记录的 VPS 原有内核及启动镜像，只恢复受管启动设置，必要时重启并验收管理连接。各轮 v3 内核包和事务历史保留；网络参数与应用服务配置保留。",
            _ => "读取原事务状态与启动身份，沿用独立安装任务的结果，不重复安装或重启。新内核已启动时核验 BBR v3 与管理连接，确认通过后提交。"
        }),
        OperationKind.TunnelAccess => "从 VPS 核对 Tunnel 已连接、主控本机接口与公开 HTTPS 接口的响应和版本；保存检查结果，不修改 Cloudflare 路由或重启服务。\n公开网址：" + request.Options.Text("PublicUrl"),
        OperationKind.InstallComponent => (request.Options["InstallationVersions"] is JsonObject selection ? "本轮安装版本：\n" + InstallationVersions.Summary(selection, InstallationVersions.AdditionalComponents(request.Options)) + "\n\n" : "") + "在现有实例上追加安装 " + ComponentInstallations.SelectionLabel(request.Options) + "。统一核对未安装状态和端口、建立本轮恢复快照，再逐项安装并统一验收；本轮失败或取消一并恢复新增组件，保留已有协议、SSH 和网络参数。",
        OperationKind.MeasureNetwork => NetworkTuning.MeasurementSummary(request.Options),
        OperationKind.TuneNetwork => (request.Options.Text("BbrVersion", "Current") == "v3" ? "BBR 版本：Google 官方源码构建 v3，必须已有受管验收记录及对应运行证据。\n" : "BBR 版本：沿用 VPS 原有内核的可用版本。\n") + (request.Options.Text("Profile") == "EntryMeasured" ? "依据 24 小时内的方向证据，仅试调有本机发送缓冲限制证据的 TCP 发送上限，并启用 fq 与可用 BBR。保留接收缓冲、初始默认内存、初始窗口、TFO 和连接策略，不自动做全局整形。\n先保存原值与队列，再以同一路径、关键方向、多个目标复测；短连接、重传或排队代价不合格时恢复原值。复测使用同等有效载荷预算，不修改对端 VPS，不自动升级内核或重启。" : "仅启用默认接口 fq 和当前内核可用的 BBR；保留缓冲、TFO 等其他运行参数。先备份文件和实际参数/队列，再核验生效与管理连接。无需公网测速。BBR 版本同时核对模块或真实 TCP 证据，当前内核不支持时明确提示；内核升级需另行维护。"),
        OperationKind.Recover => "先核对未完成事务的真实状态，再按明确范围恢复。",
        OperationKind.Upgrade => "升级对象：" + TargetLabel(request) + "\n版本来源：" + (request.Options.Text("Source", "Fixed") == "Latest" ? "官方最新稳定版（已查询锁定）" : "应用固定版本") + "\n目标版本：" + request.Options.Text("TargetVersion") + "\n先核对状态并备份，再更新程序、重启所选服务并独立验收；失败按协议范围恢复。协议备份覆盖本机受管代理协议，恢复时须一并审阅。",
        OperationKind.Komari => "操作：" + TargetLabel(request) + (request.Options.Text("Action") == "Upgrade" ? "\n版本来源：" + (request.Options.Text("Source", "Fixed") == "Latest" ? "官方最新稳定版（已查询锁定）" : "应用固定版本") + "\n目标版本：" + request.Options.Text("TargetVersion") : "") + "\n" + (request.Options.Text("Scope") switch { "KomariAgent" => request.Options.Text("Action") == "Remove" ? "卸载当前 VPS 的 Agent，停止向主控上报；不删除主控历史数据。" : "备份并更新当前 VPS 的 Agent，保留连接配置和原启停状态。", "KomariController" => "先备份当前 VPS 的主控程序和数据；一致性备份、升级及恢复需要短暂停止主控，再恢复原启停状态。只处理主控专用备份，不包含 Tunnel。", _ => request.Options.Text("Action") == "Upgrade" ? "只升级 cloudflared 程序，保留连接 Token、服务配置及启停状态。运行中的 Tunnel 会短暂重连并验证就绪状态；失败只恢复 Tunnel 范围。" : "只轮换当前 VPS 的 Tunnel 连接 Token 并重启 Tunnel；新 Token 在执行时输入，不修改 Cloudflare DNS 或主控数据。" }),
        _ => "任务：" + request.Kind + "；组件：" + request.Options.Text("Scope", request.Options.Text("Protocol", "受管协议")) + "。操作前备份，失败按同一组件范围恢复。"
    };
}
