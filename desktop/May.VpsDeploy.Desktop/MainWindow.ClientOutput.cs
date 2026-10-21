using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task EditClientOutputRules()
    {
        var selected = scheme!; var fingerprint = ArchiveStore.Fingerprint(selected); var rules = selected["OutputRules"]?.DeepClone().AsObject() ?? ClientOutputRules.New();
        TextBox Lines(string label, string key) { var field = Field(label, rules, key); field.AcceptsReturn = true; field.Height = 90; field.MaxLength = 4096; return field; }
        var dialog = OperationDialog("输出筛选与命名", new ScrollViewer { MaxHeight = 480, Content = Column(Flag("启用输出规则", rules, "Enabled"),
            Text("筛选按源名称子串匹配，不区分大小写，每行一个词；排除优先。显示名替换为区分大小写的普通文本替换。只修改生成结果，不改源节点。", 14, true),
            Fields(Lines("包含名称（留空为全部）", "Include"), Lines("排除名称", "Exclude")),
            Fields(Lines("协议（可选，每行一个，例如 anytls、vless、ss）", "Protocols"), Choice("节点用途", rules, "Role", [("All", "全部用途"), ("entry", "仅入口"), ("landing", "仅落地")])),
            Fields(Field("替换文本", rules, "Find"), Field("替换为", rules, "Replace"), Field("输出名前缀", rules, "Prefix"), Field("输出名后缀", rules, "Suffix")),
            Choice("节点顺序", rules, "Sort", [("Source", "保留源顺序"), ("NameAscending", "按输出名升序"), ("NameDescending", "按输出名降序")])) }, "预览");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        var draft = selected.DeepClone().AsObject(); draft["OutputRules"] = rules.DeepClone(); var preview = ClientOutputRules.Preview(draft);
        var review = OperationDialog("预览输出规则", OutputPreviewContent(preview), "保存规则"); review.IsPrimaryButtonEnabled = preview.Ready;
        if (await ShowDialog(review) != ContentDialogResult.Primary) return;
        ClientOutputRules.Apply(selected, rules, fingerprint); DirtyScheme();
    }
    private UIElement OutputPreviewContent(ClientOutputPreview preview)
    {
        var stack = Column(Text("保留 " + preview.Rows.Count(r => r.Included) + " 个，筛除 " + preview.Rows.Count(r => !r.Included) + " 个。静态报告不代替固定核心校验和实际连接验收。", 14));
        foreach (var issue in preview.Issues) stack.Children.Add(Text((issue.Severity == "Error" ? "阻止生成：" : "提示：") + issue.Message, 14));
        stack.Children.Add(Text("输出顺序：" + string.Join(" → ", preview.Scheme["Nodes"]!.AsArray().Select(n => n!.Text("name"))), 13, true));
        foreach (var row in preview.Rows) stack.Children.Add(Text(row.OriginalName + (row.Included ? " → " + row.OutputName : " → 筛除") + "\n" + row.Reason, 14, !row.Included));
        stack.Children.Add(Text("客户端能力报告", 17));
        foreach (var row in ClientCapabilities.Inspect(preview.Scheme)) stack.Children.Add(Text(row.Node + " · " + (row.Client == "SingBox" ? "sing-box" : row.Client) + " · " + row.Protocol + (row.Ready ? "" : " · 无法生成") + "\n" + row.Summary, 13, true));
        return new ScrollViewer { Content = stack, MaxHeight = 480 };
    }
    private async Task PreviewClientOutput()
    {
        var review = OperationDialog("生成预览与客户端能力", OutputPreviewContent(ClientOutputRules.Preview(scheme!)), ""); review.PrimaryButtonText = ""; await ShowDialog(review);
    }
}
