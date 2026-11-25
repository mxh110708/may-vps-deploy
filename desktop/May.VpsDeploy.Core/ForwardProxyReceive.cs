using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ForwardProxyReceive
{
    public static JsonObject New() => new()
    {
        ["Version"] = 1, ["Protocol"] = "Auto", ["TrustedSources"] = new JsonArray(),
        ["ClientSources"] = new JsonArray(), ["ProbeSource"] = "", ["ProbeDestination"] = "", ["TimeoutSeconds"] = 3
    };
    public static JsonObject Normalize(JsonObject rule)
    {
        if (rule["ProxyReceive"] is not JsonObject policy || policy.Count != 7 || policy.Any(p => p.Key is not ("Version" or "Protocol" or "TrustedSources" or "ClientSources" or "ProbeSource" or "ProbeDestination" or "TimeoutSeconds")) || policy["Version"] is not JsonValue v || !v.TryGetValue<int>(out var version) || version != 1 || policy.Text("Protocol") is not ("v1" or "v2" or "Auto")) throw new OperationException("PROXY 接收策略无效，请明确选择 v1、v2 或自动识别。");
        if (rule.Text("Validation.Type") != "Tls" || rule.Text("ProxyProtocol") is not ("v1" or "v2")) throw new OperationException("PROXY 接收须显式向支持头部的 TLS 目标继续发送 v1／v2，并保留证书验收。");
        if (policy["TimeoutSeconds"] is not JsonValue timeoutValue || !timeoutValue.TryGetValue<int>(out var timeout) || timeout is < 1 or > 10) throw new OperationException("PROXY 头部总接收时限须为 1–10 秒。");
        var result = policy.DeepClone().AsObject();
        foreach (var key in new[] { "TrustedSources", "ClientSources" })
        {
            if (policy[key] is not JsonArray sources || sources.Count is < 1 or > 32 || sources.Any(s => s is not JsonValue n || !n.TryGetValue<string>(out _))) throw new OperationException("须分别填写 1–32 个可信中转网段与允许声明的客户端网段。");
            var values = sources.Select(s => TcpForwarding.Source(s!.GetValue<string>())).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            foreach (var value in values)
            {
                var net = IPNetwork.Parse(value);
                if (net.BaseAddress.IsIPv6Multicast || net.BaseAddress.AddressFamily == AddressFamily.InterNetwork && net.BaseAddress.GetAddressBytes()[0] is >= 224 and <= 239 || key == "TrustedSources" && net.PrefixLength == 0) throw new OperationException("可信中转不能覆盖整个互联网，来源网段不能是组播。");
                if (key == "TrustedSources" && !rule.Strings("AllowedSources").Select(IPNetwork.Parse).Any(a => a.BaseAddress.AddressFamily == net.BaseAddress.AddressFamily && a.PrefixLength <= net.PrefixLength && a.Contains(net.BaseAddress))) throw new OperationException("可信中转须被当前 TCP 连接来源白名单完整覆盖。");
            }
            result[key] = new JsonArray(values.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        }
        if (policy["ProbeSource"] is not JsonValue probeValue || !probeValue.TryGetValue<string>(out var probe)) throw new OperationException("请填写验收时使用的声明客户端 IP。");
        result["ProbeSource"] = TcpForwarding.Address(probe);
        if (policy["ProbeDestination"] is not JsonValue destinationValue || !destinationValue.TryGetValue<string>(out var destination)) throw new OperationException("请填写验收时声明的原目的 IP。");
        result["ProbeDestination"] = TcpForwarding.Address(destination);
        if (IPAddress.Parse(result.Text("ProbeSource")).AddressFamily != IPAddress.Parse(result.Text("ProbeDestination")).AddressFamily) throw new OperationException("验收声明的客户端与原目的 IP 须使用同一地址族。");
        if (!result.Strings("ClientSources").Select(IPNetwork.Parse).Any(n => n.Contains(IPAddress.Parse(result.Text("ProbeSource"))))) throw new OperationException("验收声明来源须位于允许的客户端网段内。");
        return result;
    }
    public static string ProbeProtocol(JsonObject rule) => rule.Text("ProxyReceive.Protocol") == "v1" ? "v1" : "v2";
    public static IPAddress ProbeDestination(JsonObject rule)
    {
        return IPAddress.Parse(rule.Text("ProxyReceive.ProbeDestination"));
    }
    public static byte[] Header(string version, IPAddress source, int sourcePort, IPAddress destination, int destinationPort)
    {
        if (version is not ("v1" or "v2") || source.AddressFamily != destination.AddressFamily || sourcePort is < 1 or > 65535 || destinationPort is < 1 or > 65535 || source.IsIPv4MappedToIPv6 || destination.IsIPv4MappedToIPv6) throw new OperationException("PROXY 验收端点无效。");
        if (version == "v1") return Encoding.ASCII.GetBytes($"PROXY TCP{(source.AddressFamily == AddressFamily.InterNetwork ? 4 : 6)} {source} {destination} {sourcePort} {destinationPort}\r\n");
        var src = source.GetAddressBytes(); var dst = destination.GetAddressBytes();
        var result = new byte[16 + src.Length + dst.Length + 4];
        "\r\n\r\n\0\r\nQUIT\n"u8.CopyTo(result); result[12] = 0x21; result[13] = source.AddressFamily == AddressFamily.InterNetwork ? (byte)0x11 : (byte)0x21;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(14), (ushort)(result.Length - 16));
        src.CopyTo(result, 16); dst.CopyTo(result, 16 + src.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(result.Length - 4), (ushort)sourcePort); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(result.Length - 2), (ushort)destinationPort);
        return result;
    }
    public static JsonObject ProbeEvidence(JsonObject rule) => new()
    {
        ["Scope"] = "ControllerDeclaredSourceTls", ["RuleFingerprint"] = ForwardTargetGroups.Fingerprint(rule),
        ["Protocol"] = ProbeProtocol(rule), ["Source"] = rule.Text("ProxyReceive.ProbeSource"), ["Destination"] = rule.Text("ProxyReceive.ProbeDestination")
    };
    public static void RequireEvidence(JsonObject rule, JsonObject check)
    {
        if (rule["ProxyReceive"] != null && (!check.Flag("CertificateValidated") || !JsonNode.DeepEquals(check["ProxyReceive"], ProbeEvidence(rule)))) throw new OperationException("可信 PROXY 接收缺少当前规则与声明来源的 TLS 验收。");
    }
    public static string Summary(JsonObject rule) => rule["ProxyReceive"] == null ? "" : "\n可信 PROXY 接收：" + rule.Text("ProxyReceive.Protocol") + "；仅信任实际连接来源 " + string.Join("，", rule.Strings("ProxyReceive.TrustedSources")) + "；允许声明客户端 " + string.Join("，", rule.Strings("ProxyReceive.ClientSources")) + "；头部总时限 " + rule.Number("ProxyReceive.TimeoutSeconds") + " 秒；验收使用明确声明的测试来源 " + rule.Text("ProxyReceive.ProbeSource") + " → " + rule.Text("ProxyReceive.ProbeDestination") + "。不接受无头直连、UNKNOWN、LOCAL、UDP 或 TLV；只在完成可信头部及客户端网段核对后连接目标，哈希采用已验证的声明来源。此电脑须被列入可信中转才能直接验收。下游须只信任本转发端；来源并不具备密码学认证，TLS 验收不替代下游的来源授权。";
}
