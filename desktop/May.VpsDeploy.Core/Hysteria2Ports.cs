using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

// Keep ranges compact for external subscriptions; managed listeners deliberately
// have a smaller bound so a typo cannot reserve thousands of host ports.
public static class Hysteria2Ports
{
    public const int MaximumManagedPorts = 256;
    public const int DefaultInterval = 30;
    private static (int Start, int End)[] Ranges(string text)
    {
        if (text.Length is < 1 or > 1024 || text.Split(',').Length > 32) throw new OperationException("跳跃端口须为不超过 32 段的端口或范围。");
        var values = new List<(int Start, int End)>();
        foreach (var part in text.Split(','))
        {
            var match = Regex.Match(part.Trim(), "^([0-9]{1,5})(?:-([0-9]{1,5}))?$");
            if (!match.Success) throw new OperationException("跳跃端口使用逗号分隔，范围使用连字符，例如 22000,22010-22020。");
            var start = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            var end = match.Groups[2].Success ? int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture) : start;
            if (start < 1 || end > 65535 || start > end) throw new OperationException("跳跃端口须在 1–65535 内，范围起点不能大于终点。");
            values.Add((start, end));
        }
        var result = new List<(int Start, int End)>();
        foreach (var range in values.OrderBy(r => r.Start).ThenBy(r => r.End))
        {
            if (result.Count > 0 && range.Start <= result[^1].End + 1) result[^1] = (result[^1].Start, Math.Max(result[^1].End, range.End));
            else result.Add(range);
        }
        return result.ToArray();
    }
    private static string Format(IEnumerable<(int Start, int End)> values, char separator = '-') => string.Join(',', values.Select(r => r.Start == r.End ? r.Start.ToString(CultureInfo.InvariantCulture) : r.Start + separator.ToString() + r.End));
    public static string Normalize(string text) => Format(Ranges(text));
    public static bool Contains(string text, int port) => Ranges(text).Any(r => port >= r.Start && port <= r.End);
    public static int First(string text) => Ranges(text)[0].Start;
    public static int[] Expand(string text)
    {
        var ranges = Ranges(text);
        if (ranges.Sum(r => r.End - r.Start + 1) > MaximumManagedPorts) throw new OperationException("每个受管入站最多使用 256 个跳跃端口。");
        return ranges.SelectMany(r => Enumerable.Range(r.Start, r.End - r.Start + 1)).ToArray();
    }
    public static JsonArray Native(string text) => new(Ranges(text).Select(r => (JsonNode?)JsonValue.Create(r.Start.ToString(CultureInfo.InvariantCulture) + ":" + r.End.ToString(CultureInfo.InvariantCulture))).ToArray());
    public static string FromNative(JsonNode? value)
    {
        var items = value is JsonArray list ? list.ToArray() : [value];
        if (items.Length == 0 || items.Any(v => v is not JsonValue j || !j.TryGetValue<string>(out _))) throw new OperationException("Hysteria2 跳跃端口格式无效。");
        return Normalize(string.Join(',', items.Select(v => v!.ToString().Replace(':', '-'))));
    }
    public static string Authority(string text, int port)
    {
        if (!Contains(text, port)) throw new OperationException("跳跃端口必须包含节点主端口。");
        var others = Ranges(text).SelectMany(r => port < r.Start || port > r.End ? new[] { r } : new[] { (r.Start, port - 1), (port + 1, r.End) }.Where(p => p.Item1 <= p.Item2)).ToArray();
        return port.ToString(CultureInfo.InvariantCulture) + (others.Length == 0 ? "" : "," + Format(others));
    }
    public static int Interval(JsonObject options)
    {
        if (options["HopIntervalSeconds"] is not JsonValue value || !value.TryGetValue<int>(out var interval) || interval is < 5 or > 3600) throw new OperationException("端口跳跃间隔须为 5–3600 秒的整数。");
        return interval;
    }
    public static int[] ListenerPorts(JsonObject inbound) => inbound.Text("Protocol") == "Hysteria2" && inbound.Text("Options.HopPorts") != "" ? Expand(inbound.Text("Options.HopPorts")) : [inbound.Number("Listener.Port")];
    public static int[] ValidationPorts(JsonObject node) => node.Text("sing_box.type") == "hysteria2" && node["sing_box"]?["server_ports"] != null ? Expand(FromNative(node["sing_box"]!["server_ports"])) : [];
    public static bool ValidationMatches(JsonObject node, JsonNode? item)
    {
        var expected = ValidationPorts(node); if (expected.Length == 0) return true;
        return item?["HopPorts"] is JsonArray actual && actual.Count == expected.Length && actual.All(p => p is JsonValue v && v.TryGetValue<int>(out _)) && actual.Select(p => p!.GetValue<int>()).Order().SequenceEqual(expected);
    }
    public static void Apply(JsonObject clash, JsonObject sing, string text, int interval)
    {
        var ports = Normalize(text);
        if (!Contains(ports, sing.Number("server_port"))) throw new OperationException("跳跃端口必须包含节点主端口。");
        clash["ports"] = ports; clash["hop-interval"] = interval;
        sing["server_ports"] = Native(ports); sing["hop_interval"] = interval + "s";
    }
    public static JsonArray Redirects(JsonObject plan) => new(InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Inbounds")
        .Where(i => i.Flag("Enabled") && i.Text("Protocol") == "Hysteria2" && i.Text("Options.HopPorts") != "")
        .OrderBy(i => i.Number("Listener.Port")).Select(i => (JsonNode?)new JsonObject { ["Address"] = i.Text("Listener.Address"), ["Port"] = i.Number("Listener.Port"), ["Ports"] = new JsonArray(ListenerPorts(i).Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()) }).ToArray());
}
