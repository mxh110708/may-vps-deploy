using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class TuicV5
{
    public static JsonObject Options() => new() { ["ServerName"] = "", ["CongestionControl"] = "cubic", ["UdpRelayMode"] = "native", ["HeartbeatSeconds"] = 10, ["AuthTimeoutSeconds"] = 3 };
    public static void Validate(JsonObject options)
    {
        var fields = new[] { "ServerName", "CongestionControl", "UdpRelayMode", "HeartbeatSeconds", "AuthTimeoutSeconds" };
        if (options.Count != fields.Length || options.Any(p => !fields.Contains(p.Key))) throw new OperationException("TUIC v5 参数包含未知或缺少字段；不支持 v4 Token、0-RTT 或额外封装。");
        if (options.Text("CongestionControl") is not ("cubic" or "new_reno" or "bbr")) throw new OperationException("TUIC 拥塞控制请选择 cubic、new_reno 或 bbr。");
        if (options.Text("UdpRelayMode") is not ("native" or "quic")) throw new OperationException("TUIC UDP 中继请选择 native 或 quic。");
        if (options["HeartbeatSeconds"] is not JsonValue heartbeat || !heartbeat.TryGetValue<int>(out var h) || h is < 5 or > 120) throw new OperationException("TUIC 心跳须为 5–120 秒的整数。");
        if (options["AuthTimeoutSeconds"] is not JsonValue timeout || !timeout.TryGetValue<int>(out var t) || t is < 1 or > 30) throw new OperationException("TUIC 鉴权等待须为 1–30 秒的整数。");
    }
    public static string Summary(JsonObject inbound) => inbound.Text("Protocol") != "TuicV5" ? "" : " · UDP/QUIC · UUID + 密码 · SNI " + inbound.Text("Options.ServerName") + " · " + inbound.Text("Options.CongestionControl") + " · UDP " + inbound.Text("Options.UdpRelayMode") + " · 心跳 " + inbound.Number("Options.HeartbeatSeconds") + " 秒 · 鉴权等待 " + inbound.Number("Options.AuthTimeoutSeconds") + " 秒 · 0-RTT 关闭";
}
