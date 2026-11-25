using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task RemoteLibrarySourceManager()
    {
        var library = new RemoteLibrarySources(store, TemplateLibrary, new ClientSubscriptionDownload());
        while (true)
        {
            var sources = library.List(); var state = new JsonObject { ["Id"] = sources.FirstOrDefault()?.Text("Id") ?? "" };
            var picker = Choice("模板／规则来源", state, "Id", sources.Select(s => (s.Text("Id"), ClientSubscriptions.Label(s["Definition"]!.AsObject()) + " · " + s["Versions"]!.AsArray().Count + " 个固定修订")));
            picker.Tag = "RemoteLibrary.Source"; string? action = null; ContentDialog? dialog = null;
            var add = Action("登记 HTTPS 来源", () => { action = "Add"; dialog!.Hide(); return Task.CompletedTask; }); add.Tag = "RemoteLibrary.Add";
            var cached = Action("缓存、差异与历史", () => { action = "Cached"; dialog!.Hide(); return Task.CompletedTask; }); cached.IsEnabled = sources.Count > 0; cached.Tag = "RemoteLibrary.Cached";
            dialog = OperationDialog("远程模板与规则来源", Column(picker, Row(add, cached), Text("获取只保存加密缓存；审阅后加入版本库。已有方案、服务器规则和导出文件继续使用原修订。来源可含访问令牌，地址只在编辑时显示，摘要仅显示主机名。", 14, true)), "获取最新修订");
            dialog.IsPrimaryButtonEnabled = sources.Count > 0;
            var result = await ShowDialog(dialog);
            if (action == "Add")
            {
                var definition = ClientSubscriptions.New(""); definition["Name"] = "远程模板／规则"; definition["Kind"] = "Template"; definition["ExpectedSha256"] = "";
                var fields = Column(Field("名称", definition, "Name"), Choice("内容类型", definition, "Kind", [("Template", "客户端模板 JSON"), ("RuleSet", "域名／CIDR 规则集 JSON")]), Field("HTTPS URL", definition, "Url"), Field("固定 SHA-256（可留空）", definition, "ExpectedSha256"), Choice("下载网络", definition, "Network", [("System", "系统连接"), ("Direct", "直接连接"), ("Proxy", "指定代理")]), Field("代理地址（指定代理时填写）", definition, "Proxy"));
                var error = Text(""); fields.Children.Add(error); var editor = OperationDialog("登记来源", DialogScroll(fields), "保存来源");
                editor.PrimaryButtonClick += (_, args) => { try { RemoteLibrarySources.ValidateDefinition(definition); } catch (OperationException e) { error.Text = e.Message; args.Cancel = true; } };
                if (await ShowDialog(editor) == ContentDialogResult.Primary) library.Register(definition);
                continue;
            }
            if (result == ContentDialogResult.Primary) { await RunBackground("获取模板／规则固定修订", async ct => await library.FetchAsync(state.Text("Id"), ct)); action = "Cached"; }
            if (action != "Cached") return;
            var source = library.Read(state.Text("Id")); var versions = source["Versions"]!.AsArray().OfType<JsonObject>().Reverse().ToArray();
            if (versions.Length == 0) { Show("此来源尚无缓存，请先获取。", InfoBarSeverity.Informational); continue; }
            var selected = new JsonObject { ["Digest"] = versions[0].Text("Digest") };
            var version = Choice("缓存修订", selected, "Digest", versions.Select(v => (v.Text("Digest"), v.Text("Revision") + " · " + v.Text("Digest")[..12] + " · " + LocalTime(v.Text("FetchedAt"))))); version.Tag = "RemoteLibrary.Revision";
            if (await ShowDialog(OperationDialog("选择固定修订", version, "预览版本差异与使用者")) != ContentDialogResult.Primary) continue;
            var preview = library.Preview(state.Text("Id"), selected.Text("Digest"));
            if (await ShowDialog(OperationDialog("保存来源修订到版本库", Text(preview.Summary, 14, true), "保存固定修订")) != ContentDialogResult.Primary) continue;
            await RunBackground("保存来源固定修订", ct => library.ImportAsync(preview, ct));
            Show("修订已加入模板／规则库。请选择目标方案或入站，另行审阅应用。", InfoBarSeverity.Success);
        }
    }
}
