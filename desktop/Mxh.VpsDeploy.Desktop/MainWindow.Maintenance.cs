using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private JsonObject InstanceState(string relative)
    {
        var file = SafePath.Resolve(paths.Instance(relative), "deployment-state.json");
        return File.Exists(file) ? ArchiveStore.ReadJson(file) : new();
    }
    private (ContentDialog Dialog, JsonObject Options, JsonObject Query) CoreUpgradeDialog(JsonObject plan, JsonObject? previous = null)
    {
        var targets = MaintenanceTargets.ProxyCores(plan, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")));
        var options = previous?.DeepClone().AsObject() ?? new JsonObject { ["Scope"] = "Protocol", ["Source"] = "Fixed" };
        var query = new JsonObject();
        var selector = Choice("升级对象", options, "Protocol", targets.Select(t => (t.Protocol, t.Name)), preventWheelSelection: true);
        var source = Choice("版本来源", options, "Source", [("Fixed", "应用固定版本（默认）"), ("Latest", "官方最新稳定版（联网查询）")], preventWheelSelection: true);
        var details = new StackPanel { Spacing = 12 };
        var dialog = OperationDialog("代理核心升级", DialogScroll(Column(Text(plan.Text("Provider") + " / " + plan.Text("Instance"), 17),
            Text("升级此 VPS 上运行代理协议的核心程序。请选择具体服务并核对版本。", 14, true), selector, source, details)), "审阅升级");
        void Refresh()
        {
            details.Children.Clear(); options.Remove("TargetVersion"); options.Remove("ReleaseSha256");
            var target = targets.FirstOrDefault(t => t.Protocol == options.Text("Protocol"));
            dialog.IsPrimaryButtonEnabled = false;
            if (target == null) { details.Children.Add(Text("此实例还没有受管代理核心。")); return; }
            var component = ComponentUpdates.ProtocolComponent(target.Protocol);
            if (options.Text("Source") == "Latest") details.Children.Add(Action("查询官方最新稳定版", () => { query["Component"] = component; query["Protocol"] = target.Protocol; dialog.Hide(); return Task.CompletedTask; }));
            dialog.IsPrimaryButtonEnabled = UpgradeDetails(details, options, selectedInstance!, component, target.ArchivedVersion, target.TargetVersion) && target.Enabled;
            details.Children.Add(Text("服务：" + target.Service, 13, true));
            details.Children.Add(Text(target.Enabled ? "执行前核对远端状态并备份，再更新程序、重启此服务并完成独立验收。" : "该协议在归档中处于停用状态。请先在协议管理中启用，再升级并验收。", 14, true));
            details.Children.Add(Text("这里显示本地归档版本。只替换所选核心程序，保留配置、端口与凭据。协议恢复点包含本机受管代理协议，回滚前会核对范围。", 13, true));
        }
        selector.SelectionChanged += (_, _) => Refresh(); source.SelectionChanged += (_, _) => Refresh(); Refresh(); return (dialog, options, query);
    }
    private async Task UpgradeCore(JsonObject plan)
    {
        var relative = selectedInstance!; JsonObject? previous = null;
        while (true)
        {
            var sheet = CoreUpgradeDialog(plan, previous); var result = await ShowDialog(sheet.Dialog);
            if (sheet.Query.Count > 0)
            {
                if (!await Submit(new(OperationKind.CheckComponentUpdate, relative, sheet.Query))) return;
                previous = sheet.Options; SelectPage("instances"); continue;
            }
            if (result == ContentDialogResult.Primary) await Submit(new(OperationKind.Upgrade, relative, sheet.Options));
            return;
        }
    }
    private UIElement MonitoringControls(JsonObject plan, JsonObject state)
    {
        var rows = MaintenanceTargets.Monitoring(plan, state).Select(target =>
        {
            var needsCheck = target.RequiresVerification || !target.Installed && state.Flag("MonitoringInventory." + (target.Scope == "Tunnel" ? "Cloudflared" : target.Scope) + ".Installed");
            var button = needsCheck
                ? Action("核对并纳管", () => Submit(new(OperationKind.HealthAudit, selectedInstance!, new())))
                : target.Installed ? Action(target.Scope == "KomariAgent" ? "管理 Agent" : target.Scope == "KomariController" ? "管理主控" : "管理 Tunnel", () => ManageMonitoring(plan, target.Scope))
                : Action(target.Scope == "KomariAgent" ? "安装 Agent" : target.Scope == "KomariController" ? "安装主控" : "安装 Tunnel", () => InstallationDialog(plan, target.Scope));
            return SettingRow(target.Name, target.Status + " · " + target.Description, target.Scope == "Tunnel" ? Symbol.Link : Symbol.View, button);
        }).ToArray();
        var group = SettingsGroup(rows);
        return MaintenanceTargets.Monitoring(plan, state).Single(t => t.Scope == "Tunnel").Installed ? Column(group, TunnelAccessPanel(plan, state)) : group;
    }
    private (ContentDialog Dialog, JsonObject Options, JsonObject Query) MonitoringDialog(JsonObject plan, JsonObject state, string scope, JsonObject? previous = null)
    {
        var target = MaintenanceTargets.Monitoring(plan, state).Single(t => t.Scope == scope);
        if (!target.Installed) throw new OperationException("当前实例没有此组件的受管安装记录。请先核对实际状态。");
        var versions = ArchiveStore.ReadJson(paths.Resolve("config/versions.json"));
        var options = previous?.DeepClone().AsObject() ?? new JsonObject { ["Scope"] = scope, ["Source"] = "Fixed" };
        var query = new JsonObject();
        var actions = Choice("操作", options, "Action", scope switch
        {
            "KomariAgent" => [("Upgrade", "升级 Agent"), ("Remove", "卸载 Agent")],
            "KomariController" => [("Upgrade", "升级主控"), ("Backup", "创建主控一致性备份"), ("Restore", "恢复主控专用备份")],
            _ => [("Upgrade", "升级 cloudflared 程序"), ("RotateToken", "轮换 Tunnel 连接 Token")]
        }, preventWheelSelection: true);
        var source = Choice("版本来源", options, "Source", [("Fixed", "应用固定版本（默认）"), ("Latest", "官方最新稳定版（联网查询）")], preventWheelSelection: true);
        var details = new StackPanel { Spacing = 12 };
        var dialog = OperationDialog(target.Name, DialogScroll(Column(Text(plan.Text("Provider") + " / " + plan.Text("Instance"), 17),
            Text(target.Description, 14, true), actions, source, details)), "审阅操作");
        void Refresh()
        {
            details.Children.Clear(); options.Remove("Backup"); options.Remove("TargetVersion"); options.Remove("ReleaseSha256"); dialog.IsPrimaryButtonEnabled = true;
            source.Visibility = options.Text("Action") == "Upgrade" ? Visibility.Visible : Visibility.Collapsed;
            if (options.Text("Action") == "Upgrade")
            {
                var component = ComponentUpdates.ScopeComponent(scope);
                if (options.Text("Source") == "Latest") details.Children.Add(Action("查询官方最新稳定版", () => { query["Component"] = component; query["Scope"] = scope; dialog.Hide(); return Task.CompletedTask; }));
                var archived = ComponentUpdates.MonitoringVersion(plan, state, scope); if (archived == "") archived = "未记录";
                dialog.IsPrimaryButtonEnabled = UpgradeDetails(details, options, selectedInstance!, component, archived, MaintenanceTargets.TargetVersion(scope, versions));
                details.Children.Add(Text("更新此程序，保留原配置及启停状态。", 14, true));
            }
            if (scope == "KomariController")
            {
                details.Children.Add(Text("一致性备份、升级和恢复会短暂停止当前 VPS 的主控，完成后恢复原启停状态。只包含主控程序与数据。", 14, true));
                if (options.Text("Action") == "Restore")
                {
                    var root = SafePath.Resolve(paths.Instance(selectedInstance!), "komari-backups");
                    if (Directory.Exists(root)) SafePath.CheckTree(root);
                    var backups = Directory.Exists(root) ? Directory.EnumerateFiles(root, "*.json").Select(ArchiveStore.ReadJson).Where(b => b.At("IncludeTunnel") != null && !b.Flag("IncludeTunnel") && b.Text("RemoteBackup") != "").ToArray() : [];
                    details.Children.Add(Choice("主控专用恢复点", options, "Backup", backups.Select(b => (b.Text("RemoteBackup"), LocalTime(b.Text("At")))), preventWheelSelection: true));
                    dialog.IsPrimaryButtonEnabled = backups.Length > 0;
                    if (backups.Length == 0) details.Children.Add(Text("还没有主控专用恢复点。请先创建一致性备份。", 14, true));
                }
            }
            if (scope == "KomariAgent" && options.Text("Action") == "Remove") details.Children.Add(Text("卸载本机 Agent 并停止上报。主控中保存的历史数据不会删除；以后重新部署 Agent 才会恢复上报。", 14, true));
            if (scope == "Tunnel") details.Children.Add(Text(options.Text("Action") == "Upgrade" ? "只更新 cloudflared 程序，保留连接 Token、服务配置及启停状态。运行中的 Tunnel 会短暂重连并验证就绪状态。" : "只更新本机 Tunnel 的连接 Token，并重启 Tunnel。新 Token 在执行时输入；不会修改 Cloudflare DNS。", 14, true));
            details.Children.Add(Text(scope == "KomariController" ? "Agent 和 Tunnel 分别维护，不包含在主控备份与恢复中。" : scope == "KomariAgent" ? "这里不升级代理核心，也不操作监控主控或 Tunnel。" : "主控程序、监控数据和 Agent 保持原配置。", 13, true));
        }
        actions.SelectionChanged += (_, _) => Refresh(); source.SelectionChanged += (_, _) => Refresh(); Refresh(); return (dialog, options, query);
    }
    private async Task ManageMonitoring(JsonObject plan, string scope)
    {
        var relative = selectedInstance!; JsonObject? previous = null;
        while (true)
        {
            var sheet = MonitoringDialog(plan, InstanceState(relative), scope, previous); var result = await ShowDialog(sheet.Dialog);
            if (sheet.Query.Count > 0)
            {
                if (!await Submit(new(OperationKind.CheckComponentUpdate, relative, sheet.Query))) return;
                previous = sheet.Options; SelectPage("instances"); continue;
            }
            if (result == ContentDialogResult.Primary)
            {
                if (sheet.Options.Text("Action") != "Upgrade") sheet.Options.Remove("Source");
                await Submit(new(OperationKind.Komari, relative, sheet.Options));
            }
            return;
        }
    }
}
