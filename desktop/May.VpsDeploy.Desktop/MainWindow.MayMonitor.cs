using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ManageMayMonitorDialog()
    {
        var instances = store.ListInstances().Where(i => { var state = InstanceLifecycle.Read(store, i.RelativePath, i.Plan); return state.Managed && !state.NeedsRecovery; }).ToArray();
        if (instances.Length == 0) throw new OperationException("先接入一个已完成纳管的实例，再显式部署 May Monitor。");
        var model = new JsonObject { ["Instance"] = instances[0].RelativePath, ["Role"] = "Server", ["Action"] = "Check" };
        var instance = Choice("目标实例", model, "Instance", instances.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance"))));
        var role = Choice("May 组件", model, "Role", [("Server", "May Monitor 服务端"), ("Agent", "May Monitor Agent")]);
        var action = Choice("操作", model, "Action", new[] { ("Check", "只读核对"), ("Install", "安装 May 组件（与 Komari 并存）"), ("Upgrade", "升级到配套固定版本"), ("ConfigureRead", "应用本机只读授权（服务端）"), ("Backup", "一致性备份"), ("Restore", "恢复 May 备份"), ("Enable", "启用 May 服务"), ("Disable", "停用 May 服务"), ("Remove", "移除 May 程序（保留数据）") });
        instance.Tag = "MayMonitor.Instance"; role.Tag = "MayMonitor.Role"; action.Tag = "MayMonitor.Action";
        var fields = new StackPanel { Spacing = 14 }; var error = Text("", 13, true); error.Tag = "MayMonitor.Validation";
        var panel = Column(instance, Fields(role, action), fields, Text("May Monitor 使用独立服务与私有目录。可以先迁移单个节点，旧 Komari、Cloudflare Tunnel 和代理服务继续保留；这里只操作明确选择的 May 组件。", 13, true), error);
        JsonObject configuration = new(); string? readSource = null;
        void Render()
        {
            fields.Children.Clear(); error.Text = ""; readSource = null;
            var selected = instances.Single(i => i.RelativePath == model.Text("Instance"));
            var section = MayMonitorLifecycle.Section(model.Text("Role")); configuration = new();
            var selectedAction = model.Text("Action");
            var stateFile = SafePath.Resolve(paths.Instance(selected.RelativePath), "deployment-state.json");
            var storedState = File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new JsonObject();
            var known = storedState[section] as JsonObject;
            fields.Children.Add(Text(known == null ? "尚未核对 May 组件；可先执行只读核对。" : "上次核对：" + (known.Flag("Installed") ? known.Text("Version") + (known.Flag("Active") ? " · 运行中" : " · 已停止") : "尚未安装／已移除") + "；当前状态将在执行时重新核对。", 12, true));
            if (selectedAction is "Install" or "Upgrade")
            {
                if (model.Text("Role") == "Server")
                {
                    configuration["Port"] = selected.Plan.Number(section + ".Port", 25775); configuration["Username"] = selected.Plan.Text(section + ".Username", "admin");
                    var port = Field("回环监听端口", configuration, "Port", numeric: true); var name = Field("May 管理员名称", configuration, "Username");
                    if (selectedAction == "Upgrade") { port.IsReadOnly = true; name.IsReadOnly = true; }
                    fields.Children.Add(Fields(port, name));
                    fields.Children.Add(Text("默认只监听 127.0.0.1。HTTPS 或 Tunnel 的发布配置另行审阅；不会改动现有 Komari 域名。新管理员密码在执行时输入并加密归档。", 12, true));
                }
                else
                {
                    configuration["Endpoint"] = selected.Plan.Text(section + ".Endpoint");
                    var endpoint = Field("May 服务端 HTTPS 地址", configuration, "Endpoint"); endpoint.IsReadOnly = selectedAction == "Upgrade"; fields.Children.Add(endpoint);
                    fields.Children.Add(Text("先在 May 服务端创建节点，执行时输入该节点的 Agent Token。安装会核对 Token 对应的节点身份，不复用旧 Komari Token。远程控制和自动更新保持关闭。", 12, true));
                }
                try { var asset = MayMonitorLifecycle.Asset(paths, model.Text("Role")); fields.Children.Add(Text("配套版本 " + asset.Text("Version") + " · SHA-256 已固定", 12, true)); }
                catch (OperationException safe) { fields.Children.Add(Text(safe.Message, 12, true)); }
            }
            else if (selectedAction == "ConfigureRead")
            {
                if (model.Text("Role") != "Server") { fields.Children.Add(Text("只读授权只应用于 May 服务端。", 13, true)); return; }
                try
                {
                    var connection = MonitorArchive.Load() ?? throw new OperationException("请先保存本机只读连接与节点绑定。"); readSource = connection.Identity;
                    configuration["ReadAuthorization"] = new JsonObject { ["Sha256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(connection.Token))), ["Clients"] = new JsonArray(connection.Bindings.Values.Order(StringComparer.Ordinal).Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()), ["ExpiresAt"] = DateTimeOffset.UtcNow.AddDays(30).ToString("O") };
                    fields.Children.Add(Text("来源 " + connection.Endpoint.AbsoluteUri + " · " + connection.Bindings.Count + " 个节点 · 有效期 30 天", 13));
                    fields.Children.Add(Text("只下发摘要和范围；不会发送或保存本机原始只读令牌。应用后在监测页刷新，核对外部 HTTPS 路径。", 12, true));
                }
                catch (OperationException safe) { fields.Children.Add(Text(safe.Message, 13, true)); }
            }
            else if (selectedAction == "Restore")
            {
                var backups = MayMonitorLifecycle.Backups(store, model.Text("Instance"), model.Text("Role"));
                configuration["RestoreTask"] = ""; configuration["RestoreSha256"] = "";
                var picker = Choice("同实例、同 May 组件的恢复点", configuration, "RestoreTask", backups.Select(b => (b.Text("TaskId"), b.Text("CreatedAt") + " · " + b.Text("TaskId")[..8])));
                void Pick() { var value = backups.SingleOrDefault(b => b.Text("TaskId") == configuration.Text("RestoreTask")); configuration["RestoreSha256"] = value?.Text("Sha256") ?? ""; }
                picker.SelectionChanged += (_, _) => Pick(); Pick(); fields.Children.Add(picker);
                if (backups.Count == 0) fields.Children.Add(Text("没有可用于恢复的 May 一致性备份；不会使用 Komari 或协议恢复点。", 12, true));
            }
        }
        instance.SelectionChanged += (_, _) => Render(); role.SelectionChanged += (_, _) => Render(); action.SelectionChanged += (_, _) => Render(); Render();
        OperationRequest? request = null;
        var dialog = OperationDialog("May Monitor 部署与维护", panel, "审阅操作");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var options = new JsonObject { ["Role"] = model.Text("Role"), ["Action"] = model.Text("Action"), ["Configuration"] = configuration.DeepClone() };
                if (readSource != null) options["ReadSourceIdentity"] = readSource;
                MayMonitorLifecycle.Validate(options); request = new(OperationKind.MayMonitor, model.Text("Instance"), options);
            }
            catch (OperationException safe) { args.Cancel = true; error.Text = safe.Message; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary || request == null) return;
        await Submit(request);
    }
}
