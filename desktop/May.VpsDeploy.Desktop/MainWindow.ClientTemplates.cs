using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private ClientTemplateStore TemplateLibrary => new(store, new ExternalToolRunner(), new ValidationAssets(paths, "windows-amd64"), paths.Resolve("runtime/python/python.exe"));
    private async Task ClientTemplateLibrary()
    {
        var library = TemplateLibrary; var choiceState = new JsonObject();
        while (true)
        {
            var documents = library.List(); var selectedKey = choiceState.Text("Version");
            if (!documents.Any(d => d.Text("Id") + ":" + d.Number("Revision") == selectedKey)) choiceState["Version"] = documents[0].Text("Id") + ":" + documents[0].Number("Revision");
            JsonObject Selected() { var entry = documents.Single(d => d.Text("Id") + ":" + d.Number("Revision") == choiceState.Text("Version")); return library.Read(entry.Text("Id"), entry.Number("Revision")); }
            var choice = Choice("模板与修订", choiceState, "Version", documents.Select(d => (d.Text("Id") + ":" + d.Number("Revision"), d.Text("Name") + " · 修订 " + d.Number("Revision") + " · " + (d.Text("Clients") == "Both" ? "Mihomo + May Route" : d.Text("Clients") == "Clash" ? "Mihomo" : "May Route")))); choice.Tag = "ClientTemplates.Version";
            var detail = Text("", 13, true);
            void Details() { var d = Selected(); detail.Text = "固定核心：" + string.Join("；", d["Cores"]!.AsObject().Select(p => p.Key + " " + p.Value!.Text("Version"))) + "\n编辑会新增不可变修订，旧版本继续可选；保存模板不自动更新任何方案。"; }
            choice.SelectionChanged += (_, _) => Details(); Details();
            string? action = null; ContentDialog? dialog = null;
            var fork = Action("另存为新模板", () => { action = "Fork"; dialog!.Hide(); return Task.CompletedTask; }); fork.Tag = "ClientTemplates.Fork";
            var inspect = Action("检查依赖", () => { action = "Inspect"; dialog!.Hide(); return Task.CompletedTask; }); inspect.Tag = "ClientTemplates.Inspect";
            var restore = Action("应用记录与恢复", () => { action = "Restore"; dialog!.Hide(); return Task.CompletedTask; }); restore.Tag = "ClientTemplates.Restore";
            dialog = OperationDialog("客户端模板库", Column(choice, detail, Row(fork, inspect), restore,
                Text(scheme == null ? "打开并保存方案后，才能应用模板。" : SchemeChanged ? "当前方案有未保存修改；先保存，再审阅应用。" : "将模板应用到已保存方案“" + scheme.Text("Name") + "”，节点、凭据、订阅及导出文件保留。", 14, true)), "预览应用差异");
            dialog.IsPrimaryButtonEnabled = scheme != null && !SchemeChanged; dialog.SecondaryButtonText = "新建修订";
            var result = await ShowDialog(dialog); var selected = Selected();
            if (result == ContentDialogResult.Primary) { await ReviewClientTemplate(selected); return; }
            if (result == ContentDialogResult.Secondary || action == "Fork") { await EditClientTemplate(library.Draft(selected, action == "Fork")); continue; }
            if (action == "Inspect")
            {
                JsonObject? proof = null; await RunBackground("检查模板声明", async ct => proof = await library.InspectAsync(selected, ct));
                var rows = Column(Text("核心版本、参数、组引用及规则来源声明已检查；未下载远程规则，尚未完成真实线路验收。", 14, true));
                foreach (var dependency in proof!["Dependencies"]!.AsArray()) rows.Children.Add(Text(dependency!.Text("Format") + " · " + dependency.Text("Kind") + " · " + dependency.Text("Locator") + (dependency.Text("Status") == "PinnedArtifactAvailable" ? " · 本机归档摘要已核对" : " · 尚未获取"), 13));
                await ShowDialog(OperationDialog("模板依赖", DialogScroll(rows), "完成")); continue;
            }
            if (action == "Restore") { await RestoreClientTemplate(); continue; }
            return;
        }
    }
    private async Task EditClientTemplate(JsonObject draft)
    {
        var baseline = TemplateLibrary.BuiltIn();
        var name = Field("模板名称", draft, "Name"); name.Tag = "ClientTemplates.Name";
        var target = Choice("客户端范围", draft, "Clients", [("Both", "Mihomo + May Route"), ("Clash", "仅 Mihomo"), ("SingBox", "仅 May Route")]); target.Tag = "ClientTemplates.Clients";
        var parameters = draft["Parameters"]!.AsObject();
        var fields = Fields(Field("Mihomo混合端口", parameters, "ClashMixedPort", numeric: true), Field("May Route混合端口", parameters, "RouteMixedPort", numeric: true),
            Choice("日志等级", parameters, "LogLevel", new[] { "debug", "info", "warn", "error" }.Select(s => (s, s))), Choice("默认路由模式", parameters, "Mode", [("rule", "规则"), ("global", "全局"), ("direct", "直连")]), Field("TUN MTU（0保留原值）", parameters, "TunMtu", numeric: true));
        TextBox Editor(string header, string text, string tag) => new() { Header = header, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 210, MaxLength = ClientTemplates.MaximumBaseBytes, Tag = tag, Text = text };
        var layout = Editor("地区与业务布局 JSON", draft["Layout"]!.ToJsonString(new() { WriteIndented = true }), "ClientTemplates.Layout");
        var clash = Editor("Mihomo基础 YAML", draft.Text("Bases.Clash", baseline.Text("Bases.Clash")), "ClientTemplates.Clash");
        var sing = Editor("May Route基础 JSON", draft.Text("Bases.SingBox", baseline.Text("Bases.SingBox")), "ClientTemplates.SingBox");
        var errorText = Text("", 13); var content = Column(name, target, fields, Flag("允许局域网访问混合监听", parameters, "AllowLan"), Flag("Mihomo允许IPv6", parameters, "ClashIpv6"),
            Text("版本只保存通用基础配置、参数和分组。固定代理及订阅请使用节点来源功能。下面的完整基础内容可修改DNS和规则；参数区会覆盖同名监听／日志／模式字段。新修订绑定当前配套核心。", 13, true),
            Details("高级布局与完整基础配置", Column(layout, clash, sing)), errorText);
        var dialog = OperationDialog("编辑模板 · 修订 " + draft.Number("Revision"), DialogScroll(content), "检查并保存新修订");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                draft["Layout"] = JsonNode.Parse(layout.Text)?.AsObject() ?? throw new OperationException("布局JSON为空。");
                var bases = new JsonObject(); foreach (var format in ClientSchemes.Formats(new JsonObject { ["OutputClients"] = draft.Text("Clients") })) bases[format] = format == "Clash" ? clash.Text : sing.Text;
                draft["Bases"] = bases; TemplateLibrary.BindCurrentCores(draft); ClientTemplates.Validate(draft); errorText.Text = "";
            }
            catch (Exception e) when (e is OperationException or System.Text.Json.JsonException or InvalidOperationException) { args.Cancel = true; errorText.Text = e is OperationException ? e.Message : e is System.Text.Json.JsonException ? "布局JSON格式无效。" : "模板字段类型无效，请检查布局和参数。"; }
        };
        while (await ShowDialog(dialog) == ContentDialogResult.Primary)
        {
            try { await RunBackground("检查并保存模板修订", ct => TemplateLibrary.SaveVersionAsync(draft, ct)); Show("模板新修订已保存；现有方案继续使用原版本。", InfoBarSeverity.Success); return; }
            catch (Exception e) when (e is OperationException or OperationCanceledException) { errorText.Text = e is OperationCanceledException ? "保存已取消，原版本保留。" : e.Message; }
        }
    }
    private async Task ReviewClientTemplate(JsonObject document)
    {
        if (scheme == null || SchemeChanged) throw new OperationException("请先保存当前方案，再审阅模板差异。");
        ClientTemplateReview? preview = null;
        await RunBackground("预览模板差异", async ct => preview = await TemplateLibrary.PreviewAsync(scheme.Text("Id"), document.Text("Id"), document.Number("Revision"), ct));
        var dialog = OperationDialog("模板应用差异", DialogScroll(Column(Text(preview!.Summary, 14), Text("只更新Deploy私人归档；不写入正在运行的Route／Mihomo，也不会更改系统代理。", 13, true))), "应用此修订");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        string? application = null; await RunBackground("应用模板修订", async ct => application = await TemplateLibrary.ApplyAsync(preview, ct));
        if (application != "") { scheme = store.ReadSecret(ServerOutboundRouting.SchemeFile(paths, scheme.Text("Id"))); RememberScheme(); }
        Navigate("clients"); Show(application == "" ? "模板版本和配置相同，保留现有候选，无需重复应用。" : "模板已应用；请重新生成、校验并审阅导出。可从模板库的应用记录恢复。", InfoBarSeverity.Success);
    }
    private async Task RestoreClientTemplate()
    {
        var journals = ClientTemplates.Journals(store).Where(j => j.Text("Phase") != "RolledBack" && (scheme == null || j.Text("SchemeId") == scheme.Text("Id"))).OrderByDescending(j => j.Text("At")).ToArray();
        if (journals.Length == 0) { await ShowDialog(OperationDialog("模板应用记录", Text("当前没有可恢复的应用。"), "完成")); return; }
        if (scheme != null && SchemeChanged) throw new OperationException("请先保存或放弃方案草稿，再恢复基础配置。");
        var state = new JsonObject { ["Id"] = journals[0].Text("Id") };
        var picker = Choice("应用记录", state, "Id", journals.Select(j => (j.Text("Id"), LocalTime(j.Text("At")) + " · " + (j.Text("Phase") is "Prepared" or "UndoPrepared" ? "待核对" : "已完成") + " · 方案 " + j.Text("SchemeId")[..8]))); picker.Tag = "ClientTemplates.Application";
        if (await ShowDialog(OperationDialog("模板应用记录", picker, "审阅恢复")) != ContentDialogResult.Primary) return;
        var preview = TemplateLibrary.PreviewRestore(state.Text("Id"));
        if (await ShowDialog(OperationDialog("恢复模板基础配置", Text(preview.Summary), "恢复")) != ContentDialogResult.Primary) return;
        TemplateLibrary.Restore(preview);
        if (scheme != null) { scheme = store.ReadSecret(ServerOutboundRouting.SchemeFile(paths, scheme.Text("Id"))); RememberScheme(); Navigate("clients"); }
        Show("模板基础配置已恢复，节点与已导出文件保留。", InfoBarSeverity.Success);
    }
}
