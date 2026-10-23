using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private OperationRequest? activeOperation;
    private ContentDialog OperationDialog(string title, UIElement content, string primary) => new()
    {
        XamlRoot = shell.XamlRoot, Title = title, Content = content, PrimaryButtonText = primary,
        CloseButtonText = "返回", DefaultButton = ContentDialogButton.None
    };
    private ScrollViewer DialogScroll(UIElement content) => new()
    {
        Content = content, MaxHeight = Math.Max(240, Math.Min(610, shell.XamlRoot.Size.Height - 230)),
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Auto
    };
    private UIElement ReviewContent(JsonObject plan, OperationKind kind, JsonObject? state = null)
    {
        var panel = new StackPanel { Spacing = 16 };
        panel.Children.Add(Text(kind is OperationKind.Resume or OperationKind.ResumeImport ? "按已保存的草稿继续；本页参数尚不代表检查通过。" : "核对对象、改动和执行顺序。确认后才连接服务器。", 14, true));
        foreach (var section in DeploymentReview.Sections(plan, kind, state))
        {
            var rows = new StackPanel { Spacing = 10 };
            rows.Children.Add(Text(section.Title, 17));
            foreach (var item in section.Items)
            {
                var row = new Grid { ColumnSpacing = 18 };
                row.ColumnDefinitions.Add(new() { Width = new GridLength(118) }); row.ColumnDefinitions.Add(new());
                row.Children.Add(Text(item.Label, 14, true)); var value = Text(item.Value, 14); value.IsTextSelectionEnabled = true; Grid.SetColumn(value, 1); row.Children.Add(value); rows.Children.Add(row);
            }
            panel.Children.Add(Card(rows));
        }
        return DialogScroll(panel);
    }
    private async Task<bool> ReviewOperation(ReviewedOperation review)
    {
        var request = review.Request;
        if (request.Kind == OperationKind.ServerOutbound) return await ShowDialog(OperationDialog("审阅服务器固定下一跳", DialogScroll(Column(Text(request.InstanceRelativePath.Replace("/May-VPS-Deploy", ""), 17), Text(review.Summary))), "确认并执行")) == ContentDialogResult.Primary;
        if (request.Kind == OperationKind.TcpForward) return await ShowDialog(OperationDialog(request.Options.Text("Action") == "Check" ? "审阅 TCP 转发检查" : "审阅 TCP 转发变更", DialogScroll(Column(Text(request.InstanceRelativePath.Replace("/May-VPS-Deploy", ""), 17), Text(review.Summary))), "确认并执行")) == ContentDialogResult.Primary;
        if (request.Kind == OperationKind.UdpForward) return await ShowDialog(OperationDialog(request.Options.Text("Action") == "Check" ? "审阅 UDP 转发检查" : "审阅 UDP 转发变更", DialogScroll(Column(Text(request.InstanceRelativePath.Replace("/May-VPS-Deploy", ""), 17), Text(review.Summary))), "确认并执行")) == ContentDialogResult.Primary;
        if (request.Kind == OperationKind.InstallComponent) return await ShowDialog(OperationDialog("审阅追加安装计划", InstallationReview(request), "开始安装")) == ContentDialogResult.Primary;
        if (request.Kind is OperationKind.Deploy or OperationKind.ConnectExisting or OperationKind.Resume or OperationKind.ResumeImport)
        {
            var plan = request.Options["Plan"] as JsonObject ?? ArchiveStore.ReadJson(SafePath.Resolve(paths.Instance(request.InstanceRelativePath), "deployment-plan.json"));
            var title = request.Kind is OperationKind.ConnectExisting or OperationKind.ResumeImport ? "审阅接入计划" : "审阅部署计划";
            var primary = request.Kind switch { OperationKind.ConnectExisting => "开始接入", OperationKind.ResumeImport => "继续接入", OperationKind.Resume => "继续部署", _ => "开始部署" };
            var stateFile = SafePath.Resolve(paths.Instance(request.InstanceRelativePath), "deployment-state.json");
            var state = request.Kind is OperationKind.Resume or OperationKind.ResumeImport && File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : null;
            var accepted = await ShowDialog(OperationDialog(title, ReviewContent(plan, request.Kind, state), primary)) == ContentDialogResult.Primary;
            if (accepted && request.Kind is OperationKind.Deploy or OperationKind.Resume) testSession?.PrepareReviewedDeployment(plan);
            return accepted;
        }
        return await ConfirmAsync(new("审阅并执行", request.InstanceRelativePath.Replace("/May-VPS-Deploy", "") + "\n\n" + review.Summary), CancellationToken.None);
    }
    private async Task<OperationRequest?> ResolveExistingDraft(OperationRequest request)
    {
        if (request.Kind is not (OperationKind.Deploy or OperationKind.ConnectExisting)) return request;
        var file = SafePath.Resolve(paths.Instance(request.InstanceRelativePath), "deployment-plan.json");
        if (!File.Exists(file)) return request;
        var plan = ArchiveStore.ReadJson(file); var status = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan);
        selectedInstance = request.InstanceRelativePath;
        if (!status.CanContinue)
        {
            SelectPage("instances"); Show(status.NeedsRecovery ? "该实例有未确认事务，请先核对恢复状态。" : "该实例已有归档。可以维护现有实例，或审阅删除本地归档后重新创建。", InfoBarSeverity.Warning); return null;
        }
        var content = Column(Text(plan.Text("Provider") + " / " + plan.Text("Instance"), 17), Text(status.Label), Text(status.LastError),
            Text("继续时使用已保存的部署参数。本次表单中的改动不会替换原草稿；如要干净重建，请先到实例页删除本地归档。", 14, true));
        var dialog = OperationDialog("发现未完成草稿", content, status.ContinueKind == OperationKind.ResumeImport ? "继续接入草稿" : "继续部署草稿"); dialog.SecondaryButtonText = "查看实例";
        var result = await ShowDialog(dialog);
        if (result == ContentDialogResult.Secondary) SelectPage("instances");
        return result == ContentDialogResult.Primary ? new(status.ContinueKind, request.InstanceRelativePath, new JsonObject()) : null;
    }
    private static string StageLabel(string stage) => stage switch
    {
        "audit" => "系统审计", "management-key" => "准备管理密钥", "deployment-baseline-arm" => "部署基线备份", "bootstrap-access" => "建立管理访问", "base-system" => "系统准备",
        "ssh-transition" => "管理入口切换", "target-audit" => "Reality 目标检查", "certbot-dns-setup" => "证书配置", "local-https-target" => "本机 HTTPS 配置",
        "deployment-commit" => "部署提交", "maintenance-transaction-status" => "事务状态核对", "无需回滚" => "草稿状态核对",
        "installation-preflight" => "追加安装前核对", "installation-backup" => "组件恢复快照", "component-install" => "安装所选组件",
        "monitoring-component-install" => "安装监控与访问组件", "component-install-preflight" => "核对组件布局与端口",
        "installation-firewall" or "component-firewall-add" => "新协议防火墙放行", "installation-validation" => "新增组件验收",
        "installation-archive" => "更新实例归档", "installation-commit" => "确认追加安装完成", "maintenance-komari" => "监控组件维护",
        "maintenance-transaction-commit" => "确认维护完成", "protocol-migration-trigger-rollback" => "按组件范围恢复",
        "network-tuning" => "网络调优", "validate" => "独立验收", "health" => "健康检查", "import" => "接入识别",
        "network-connection" => "核对管理连接", "network-measurement" => "测量实际线路", "network-analysis" => "生成网络建议",
        "network-preflight" => "核对网络布局", "network-backup" => "建立网络恢复点", "network-apply" => "应用网络参数",
        "network-retest" => "复测实际线路", "network-completion" => "确认网络结果", "network-audit" => "采集网络状态",
        "kernel-check" => "检查 BBR 与启动兼容性", "kernel-install" => "安装受管 BBR v3 内核", "kernel-state" => "核对内核事务",
        "component-release-check" or "component-release-latest" => "查询并锁定官方稳定版", "proxy-core-upgrade" => "更新所选代理核心",
        "kernel-upload" => "上传内置内核包", "kernel-wait" => "等待内核任务", "kernel-ready" => "内核安装完成，待重启", "kernel-reboot" => "单次重启到 BBR v3",
        "kernel-accept" => "验收运行内核与管理入口", "kernel-rollback" => "回退原有内核",
        _ when stage.StartsWith("component-install-", StringComparison.Ordinal) && ComponentInstallations.Components.Contains(stage[18..]) => "安装 " + ComponentInstallations.Label(stage[18..]),
        _ when stage.StartsWith("target-audit-", StringComparison.Ordinal) => "审计 Reality 目标",
        _ when stage.StartsWith("certbot-dns-", StringComparison.Ordinal) => "申请 AnyTLS 可信证书", _ => stage
    };
    private static string TaskMessage(TaskRecord record)
    {
        var message = OutcomeLabel(record.Outcome) + " · " + StageLabel(record.Stage);
        if (!string.IsNullOrEmpty(record.SafeError)) message += "\n" + record.SafeError;
        if (!string.IsNullOrEmpty(record.NextAction)) message += "\n下一步：" + record.NextAction;
        if (!string.IsNullOrEmpty(record.ErrorCode)) message += "\n错误代码：" + record.ErrorCode;
        return message;
    }
    private ContentDialog HostIdentityDialog(HostIdentity identity)
    {
        var label = activeOperation?.InstanceRelativePath.Replace("/May-VPS-Deploy", "") ?? "当前服务器";
        var fingerprint = Text(identity.Sha256Fingerprint, 14); fingerprint.IsTextSelectionEnabled = true;
        var reference = Field("粘贴独立取得的 SHA256 指纹（可选）", new JsonObject(), "Fingerprint"); reference.PlaceholderText = "可粘贴服务商控制台命令的整行输出";
        var comparison = Text("首次连接还没有本地记录。可独立核对，或明确选择信任本次身份。", 14, true);
        var file = identity.Algorithm.Contains("ed25519", StringComparison.Ordinal) ? "ssh_host_ed25519_key.pub" : identity.Algorithm.Contains("ecdsa", StringComparison.Ordinal) ? "ssh_host_ecdsa_key.pub" : "ssh_host_rsa_key.pub";
        var command = Text("ssh-keygen -lf /etc/ssh/" + file + " -E sha256", 14); command.IsTextSelectionEnabled = true;
        var content = Column(Text(label, 17), Text(identity.Host + " · SSH 端口 " + identity.Port),
            Text("这是服务器的 SSH 身份指纹，用于记住你首次信任的服务器。以后身份相同自动通过；身份改变时停止连接。", 14, true),
            Card(Column(Text("本次服务器指纹", 14, true), fingerprint,
                Action("复制指纹", () => { var data = new global::Windows.ApplicationModel.DataTransfer.DataPackage(); data.SetText(identity.Sha256Fingerprint); global::Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data); return Task.CompletedTask; }, allowDuringTask: true))),
            reference, comparison,
            Details("如何独立核对", Column(Text("在服务商网页控制台 / VNC 登录该 VPS，运行下面的命令，把输出指纹与上面比较。不要用当前待信任的 SSH 连接作为独立证据。", 14, true), command, Text("主机密钥算法：" + identity.Algorithm, 14, true))),
            Text("未提供独立指纹时，选择信任只表示你接受首次连接身份，不表示已独立核验。人工确认期间不占用 SSH 连接超时。", 14, true));
        var dialog = OperationDialog("确认首次连接的服务器", DialogScroll(content), "信任并连接");
        reference.TextChanged += (_, _) =>
        {
            var result = HostFingerprint.Compare(reference.Text, identity.Sha256Fingerprint);
            dialog.IsPrimaryButtonEnabled = result is FingerprintComparison.Empty or FingerprintComparison.Match;
            dialog.PrimaryButtonText = result == FingerprintComparison.Match ? "核对一致并连接" : "信任并连接";
            comparison.Text = result switch { FingerprintComparison.Match => "指纹一致，可以建立连接。", FingerprintComparison.Mismatch => "指纹不一致，已阻止连接。请先核对实例和来源。", FingerprintComparison.Invalid => "未识别到唯一的完整 SHA256 指纹，请核对粘贴内容。", _ => "尚未独立核对。只有确定这是你的服务器时才选择信任。" };
        };
        return dialog;
    }
    private Task<bool> ConfirmHostIdentity(HostIdentity identity, CancellationToken token) => OnUi(async () =>
    {
        var dialog = HostIdentityDialog(identity); using var registration = token.Register(() => DispatcherQueue.TryEnqueue(dialog.Hide));
        return await ShowDialog(dialog) == ContentDialogResult.Primary;
    }, token);
    private ContentDialog InstanceDeletionDialog(InstanceDeletionReview review) => OperationDialog("删除本地实例", DialogScroll(Column(
        Text(review.Name, 18), Text("将删除该实例在应用中保存的所有文件：计划、状态、加密凭据、管理密钥副本、实例配置与备份。", 14),
        Card(Column(Text("删除范围", 14, true), Text(review.Directory, 14), Text(review.FileCount + " 个文件 · " + FormatBytes(review.Bytes)))),
        Text("服务器上的服务继续运行。原始私钥、外部配置、其他实例和应用全局设置保留。此处不会连接服务器。", 14, true),
        Text("删除后这些材料无法从应用恢复；再次部署前仍需确保服务器状态合适。要卸载远端组件，请使用“实例退役”。", 14, true))), "删除本地实例");
    private static string FormatBytes(long value) => value >= 1048576 ? (value / 1048576d).ToString("0.0") + " MB" : value >= 1024 ? (value / 1024d).ToString("0.0") + " KB" : value + " B";
    private async Task DeleteInstance(string relative)
    {
        var deletion = new InstanceDeletion(store); var review = deletion.Review(relative);
        if (await ShowDialog(InstanceDeletionDialog(review)) != ContentDialogResult.Primary) return;
        await RunBackground("删除本地实例", token => Task.Run(() => { token.ThrowIfCancellationRequested(); deletion.Delete(review); }, token));
        selectedInstance = null; SelectPage("instances"); taskText.Text = "本地实例已删除";
        Show("已删除该实例的本地受管文件。其他实例和全局配置保留。", InfoBarSeverity.Success);
    }
}
