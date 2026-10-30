using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task WireGuardSheet(string relative, JsonObject plan)
    {
        var records = WireGuardTunnels.List(store).Where(r => WireGuardTunnels.Instances(r["Configuration"]!.AsObject()).Contains(relative))
            .OrderBy(r => WireGuardTunnels.Pending(r) ? 0 : r.Text("Phase") == "Active" ? 1 : 2).ThenByDescending(r => r.Text("UpdatedAt")).ToArray();
        var instances = store.ListInstances().Where(i => InstanceLifecycle.Read(store, i.RelativePath, i.Plan).Managed && i.RelativePath != relative).ToArray();
        var fresh = WireGuardTunnels.New(relative); var model = new JsonObject { ["Selected"] = records.FirstOrDefault(r => WireGuardTunnels.Pending(r) || r.Text("Phase") == "Active")?.Text("Configuration.Id") ?? "New", ["Action"] = "Apply" };
        var selected = Choice("隧道", model, "Selected", new[] { ("New", "新建实例间隧道") }.Concat(records.Select(r => (r.Text("Configuration.Id"), r.Text("Configuration.Name") + " · " + (WireGuardTunnels.Pending(r) ? "待恢复" : r.Text("Phase") == "Active" ? "已应用" : "已结束"))))); selected.Tag = "WireGuard.Selection";
        var content = new StackPanel { Spacing = 16 }; var error = Text("", 14, true); error.Tag = "WireGuard.Error"; JsonObject current = fresh; JsonObject? options = null;
        void Refresh()
        {
            content.Children.Clear(); error.Text = "";
            var record = records.SingleOrDefault(r => r.Text("Configuration.Id") == model.Text("Selected"));
            current = record == null ? fresh : record["Configuration"]!.DeepClone().AsObject();
            model["Action"] = record == null ? "Apply" : WireGuardTunnels.Pending(record) ? "Recover" : "Check";
            var operations = record == null ? new[] { ("Apply", "新建并验收两端隧道") } : WireGuardTunnels.Pending(record) ? [("Recover", "恢复本次两端隧道")] : record.Text("Phase") == "Active" ? [("Check", "检查双向 TCP / UDP"), ("Remove", "移除本隧道")] : [("Check", "已结束；请新建隧道")];
            var operation = Choice("操作", model, "Action", operations); operation.Tag = "WireGuard.Action"; content.Children.Add(operation);
            if (record != null)
            {
                content.Children.Add(Text(current.Text("FirstInstance") + " · " + current.Text("FirstAddress") + "/32\n↕ WireGuard · " + current.Text("Family") + "\n" + current.Text("SecondInstance") + " · " + current.Text("SecondAddress") + "/32", 16));
                content.Children.Add(Text("外层 UDP 端口：" + current.Number("FirstPort") + " / " + current.Number("SecondPort") + "；MTU：" + current.Number("Mtu") + "；保活：" + current.Number("KeepaliveSeconds") + " 秒。\n最后双向验收：" + (record.Text("LastCheck.Status") == "Failed" ? "最近检查失败" : record.Text("Validation.Status") == "Passed" ? "通过" : "尚未通过") + "\n" + record.Text("LastCheckedAt", record.Text("UpdatedAt")), 14, true));
                return;
            }
            var name = Field("隧道名称", current, "Name"); name.Tag = "WireGuard.Name"; content.Children.Add(name);
            content.Children.Add(Text("第一台：" + relative, 15));
            var second = Choice("第二台受管实例", current, "SecondInstance", instances.Select(i => (i.RelativePath, i.Plan.Text("NodeName") + " · " + i.RelativePath)), true); second.Tag = "WireGuard.Peer"; second.PlaceholderText = "请选择另一台实例"; content.Children.Add(second);
            var family = Choice("外层地址族", current, "Family", [("IPv4", "IPv4"), ("IPv6", "IPv6")]); family.Tag = "WireGuard.Family"; content.Children.Add(family);
            TextBox Input(string label, string field, bool number = false) { var input = Field(label, current, field, numeric: number); input.Tag = "WireGuard." + field; return input; }
            content.Children.Add(Fields(Input("第一台 UDP 端口", "FirstPort", true), Input("第二台 UDP 端口", "SecondPort", true)));
            content.Children.Add(Fields(Input("第一台隧道内 IPv4", "FirstAddress"), Input("第二台隧道内 IPv4", "SecondAddress")));
            content.Children.Add(Fields(Input("MTU（1280–1420）", "Mtu", true), Input("保活秒数（0，或 15–120）", "KeepaliveSeconds", true)));
            content.Children.Add(Text("仅两台受管 Debian 12／13 amd64，外层地址须实际绑定在服务器上；不支持 NAT 改写或动态地址。内层为不同的 RFC1918 IPv4，各添加对端 /32 路由。默认不保活；有需要才开启。\n两端自动生成私钥并安装缺少的 wireguard-tools；不会安装用户态隧道常驻程序。受管防火墙仅允许对端外层 UDP 与隧道内对端；对端可访问本机已有监听服务，只选择可信实例。保留既有防火墙时须预先放行。不会修改默认路由、DNS、SSH 或内核转发开关。", 14, true));
        }
        selected.SelectionChanged += (_, _) => Refresh(); Refresh();
        var dialog = OperationDialog("WireGuard 实例间隧道", DialogScroll(Column(selected, content, error)), "审阅");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try { options = new() { ["Action"] = model.Text("Action"), ["Configuration"] = current.DeepClone() }; WireGuardTunnels.Prepare(store, new(OperationKind.WireGuardTunnel, current.Text("FirstInstance"), options)); }
            catch (OperationException failure) { error.Text = failure.Message; args.Cancel = true; }
        };
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) await Submit(new(OperationKind.WireGuardTunnel, current.Text("FirstInstance"), options!));
    }
}
