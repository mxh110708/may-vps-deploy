using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task EditClientStreamNode(JsonObject original)
    {
        var selected = scheme ?? throw new OperationException("请先打开方案。"); var fingerprint = ArchiveStore.Fingerprint(selected);
        var model = new JsonObject { ["Name"] = original.Text("name"), ["Kind"] = original.Text("kind"), ["Region"] = original.Text("region_group"), ["Transit"] = original.Text("transit_group"), ["Family"] = ClientTopology.EgressFamily(original), ["Expected"] = original.Text("Egress.ExpectedAddress") };
        var regions = selected["Layout"]!.Strings("region_groups");
        var replacement = SecretField("替换连接链接（可选，留空保留原参数）"); replacement.Tag = "ClientStream.Replacement";
        var error = Text("", 14); error.Tag = "ClientStream.Error";
        var body = Column(Text(ClientStreamTransports.Label(original) + " · TLS", 16), Field("节点名称", model, "Name"),
            Choice("节点用途", model, "Kind", [("entry", "入口"), ("landing", "经入口连接的落地")]),
            Choice("入口地区组", model, "Region", regions.Select(r => (r, r))), Choice("落地连接的入口组", model, "Transit", regions.Select(r => (r, r))),
            Choice("网站出口地址族", model, "Family", [("Unknown", "未知 · 诊断时观测"), ("IPv4", "IPv4"), ("IPv6", "IPv6")]), Field("预期网站出口 IP（可选）", model, "Expected"),
            Text("名称与分组调整保留全部原生连接参数。需更换地址、鉴权或传输时，粘贴新的完整 WS／gRPC 分享链接；不会将原节点改成 Reality。链接中的显示名不覆盖上面的名称。", 14, true), replacement, error);
        var dialog = OperationDialog("编辑外部 WS／gRPC 节点", new ScrollViewer { Content = body, MaxHeight = 520 }, "保存"); JsonObject? updated = null;
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                if (ArchiveStore.Fingerprint(selected) != fingerprint) throw new OperationException("方案已变化，请重新打开编辑。");
                var name = model.Text("Name").Trim();
                if (name.Length is < 1 or > 120 || name.Any(char.IsControl) || selected["Nodes"]!.AsArray().OfType<JsonObject>().Any(n => n != original && n.Text("name") == name)
                    || regions.Contains(name) || selected["Layout"]!["business_groups"]!.AsArray().Any(g => g!.Text("name") == name) || new[] { "DIRECT", "BLOCK", "REJECT", selected.Text("Layout.default_exit_group"), selected.Text("Layout.direct_group") }.Contains(name)) throw new OperationException("名称无效或已与节点／组名重复。");
                if (!regions.Contains(model.Text("Region")) || !regions.Contains(model.Text("Transit"))) throw new OperationException("请选择有效地区组。");
                var draft = original.DeepClone().AsObject();
                if (replacement.Password.Length > 0)
                {
                    var empty = selected.DeepClone().AsObject(); empty["Nodes"] = new JsonArray(); var preview = ClientNodeImport.Preview(replacement.Password, empty, model.Text("Region"), "entry");
                    if (preview.Rows.Count != 1 || preview.Accepted != 1 || preview.Rows[0].Node?["sing_box"] is not JsonObject native || !ClientStreamTransports.IsNative(native)) throw new OperationException("请提供一条本轮支持的完整 WS／gRPC 分享链接。");
                    draft["sing_box"] = native.DeepClone(); draft["clash"] = preview.Rows[0].Node!["clash"]!.DeepClone();
                }
                if (original.Text("kind") == "landing" && model.Text("Kind") == "entry")
                { if (draft.Text("sing_box.detour") == original.Text("transit_group")) draft["sing_box"]!.AsObject().Remove("detour"); if (draft.Text("clash.dialer-proxy") == original.Text("transit_group")) draft["clash"]!.AsObject().Remove("dialer-proxy"); }
                draft["name"] = name; if (draft["sing_box"] != null) draft["sing_box"]!["tag"] = name; if (draft["clash"] != null) draft["clash"]!["name"] = name;
                draft["kind"] = model.Text("Kind"); draft["region_group"] = model.Text("Region"); draft["transit_group"] = model.Text("Transit");
                draft["Egress"] = new JsonObject { ["Family"] = model.Text("Family"), ["ExpectedAddress"] = model.Text("Expected").Trim() };
                if (model.Text("Expected").Trim() is { Length: > 0 } address && (!System.Net.IPAddress.TryParse(address, out var ip) || model.Text("Family") == "IPv4" && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || model.Text("Family") == "IPv6" && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)) throw new OperationException("预期出口 IP 与地址族不匹配。");
                if (draft["Source"] != null) draft["Source"]!["Modified"] = ClientNodeImport.ConnectionFingerprint(draft) != draft.Text("Source.Fingerprint");
                updated = draft;
            }
            catch (OperationException exception) { args.Cancel = true; error.Text = exception.Message; }
        };
        try
        {
            if (await ShowDialog(dialog) != ContentDialogResult.Primary || updated == null) return;
            ClientSchemes.RenameNodeReferences(selected, original.Text("name"), updated.Text("name")); var nodes = selected["Nodes"]!.AsArray(); nodes[nodes.IndexOf(original)] = updated; DirtyScheme();
        }
        finally { replacement.Password = ""; }
    }
}
