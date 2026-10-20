using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement NetworkTimeFields(JsonObject options)
    {
        var presets = new (string Value, string Label)[] { ("Asia/Shanghai", "中国 · 北京时间（UTC+8）"), ("Asia/Hong_Kong", "中国香港（UTC+8）"), ("Asia/Singapore", "新加坡（UTC+8）"), ("Asia/Tokyo", "日本（UTC+9）"), ("America/Los_Angeles", "美国西部 · 洛杉矶"), ("America/New_York", "美国东部 · 纽约"), ("Europe/Berlin", "德国 · 柏林"), ("Europe/London", "英国 · 伦敦"), ("UTC", "UTC"), ("Custom", "自定义时区") };
        var canonical = options.Text("TimeZoneId");
        if (TimeZoneInfo.TryConvertWindowsIdToIanaId(canonical, out var iana)) canonical = iana;
        if (canonical == "Etc/UTC") canonical = "UTC";
        var preset = new JsonObject { ["Selected"] = presets.Any(p => p.Value == canonical) ? canonical : "Custom" };
        if (preset.Text("Selected") != "Custom") options["TimeZoneId"] = canonical;
        var choice = Choice("主要使用地时区", preset, "Selected", presets);
        var custom = Field("自定义时区（IANA 或 Windows ID）", options, "TimeZoneId");
        var start = Field("高峰开始（24 小时制）", options, "PeakStartHour", numeric: true);
        var end = Field("高峰结束（24 小时制）", options, "PeakEndHour", numeric: true);
        start.PlaceholderText = "0–23，例如 20";
        end.PlaceholderText = "0–24，24 表示当天午夜";
        var format = Text("按整点填写小时数：开始填 0–23，结束填 0–24。结束填 24 表示次日 00:00；结束早于开始表示跨午夜。", 14, true);
        var description = Text("", 14, true); description.Tag = "NetworkPeakDescription";
        void Refresh()
        {
            custom.Visibility = preset.Text("Selected") == "Custom" ? Visibility.Visible : Visibility.Collapsed;
            description.Text = NetworkTuning.TimeDescription(options);
        }
        choice.SelectionChanged += (_, _) => { if (preset.Text("Selected") != "Custom") { options["TimeZoneId"] = preset.Text("Selected"); custom.Text = options.Text("TimeZoneId"); } Refresh(); };
        custom.TextChanged += (_, _) => Refresh(); start.TextChanged += (_, _) => Refresh(); end.TextChanged += (_, _) => Refresh(); Refresh();
        return Card(Column(SectionHeading("使用时间", Symbol.Clock), choice, custom, Fields(start, end), format, description));
    }
}
