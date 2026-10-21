using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientCapabilityRow(string Node, string Client, string Protocol, bool Ready, string Summary);
public static class ClientCapabilities
{
    public static IReadOnlyList<ClientCapabilityRow> Inspect(JsonObject effective)
    {
        var rows = new List<ClientCapabilityRow>();
        foreach (var node in effective["Nodes"]!.AsArray().OfType<JsonObject>())
            foreach (var client in ClientSchemes.Formats(effective))
            {
                var clash = client == "Clash"; var config = node[clash ? "clash" : "sing_box"] as JsonObject;
                if (config == null) { rows.Add(new(node.Text("name"), client, "缺少参数", false, "缺少此客户端的原生配置；不会从另一客户端猜测转换或静默省略节点。")); continue; }
                var protocol = config.Text("type"); var valid = protocol != "" && config.Text(clash ? "name" : "tag") == node.Text("name") && config.Text("server") != "" && config.Number(clash ? "port" : "server_port") is >= 1 and <= 65535;
                var tls = clash ? config.Flag("tls") || protocol is "anytls" or "trojan" or "hysteria2" or "tuic" : config.Flag("tls.enabled");
                var reality = clash ? config["reality-opts"] != null : config.Flag("tls.reality.enabled");
                var ech = clash ? config.Flag("ech-opts.enable") : config.Flag("tls.ech.enabled");
                var udp = clash && config["udp"] != null ? config.Flag("udp") ? "UDP 显式开启" : "UDP 显式关闭" : "UDP 沿用协议及核心默认值";
                rows.Add(new(node.Text("name"), client, protocol, valid, (valid ? "原生参数保留；待固定核心校验" : "服务器、端口或节点标识不完整") + " · " + (reality ? "Reality" : tls ? "TLS" : "未启用独立 TLS") + (ech ? " + ECH" : "") + " · " + udp + (node.Text("kind") == "landing" ? " · 客户端链式 " + (clash ? "dialer-proxy" : "detour") : "")));
            }
        return rows;
    }
    public static void RequireReady(JsonObject effective)
    {
        var errors = Inspect(effective).Where(r => !r.Ready).Select(r => r.Node + " / " + r.Client + "：" + r.Summary).ToArray();
        if (errors.Length != 0) throw new OperationException(string.Join("\n", errors));
    }
}
