using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class OutboundAddressPolicy
{
    public static readonly string[] Values = ["Auto", "IPv4", "IPv6", "PreferIPv4", "PreferIPv6"];
    public static bool Strict(string value) => value is "IPv4" or "IPv6";
    public static bool Dual(string value) => value is "Auto" or "PreferIPv4" or "PreferIPv6";
    public static string Validate(string value) => Values.Contains(value) ? value : throw new OperationException("地址族策略无效。");
    public static string ObservedFamily(string value) => Dual(value) ? "Auto" : Validate(value);
    public static string Legacy(JsonObject plan, string role) => Validate(plan.Text((role == "RealityEntry" ? "Reality" : "AnyTls") + ".EgressPolicy", plan.Flag((role == "RealityEntry" ? "Reality" : "AnyTls") + ".ForceIpv4Egress", true) ? "IPv4" : "Auto"));
    public static string Label(string value) => Validate(value) switch { "IPv4" => "仅 IPv4", "IPv6" => "仅 IPv6", "PreferIPv4" => "优先 IPv4，TCP 建连失败回退 IPv6", "PreferIPv6" => "优先 IPv6，TCP 建连失败回退 IPv4", _ => "自动（沿用核心默认）" };
    public static string SingStrategy(string value) => Validate(value) switch { "IPv4" => "ipv4_only", "IPv6" => "ipv6_only", "PreferIPv6" => "prefer_ipv6", _ => "prefer_ipv4" };
    public static void Endpoint(string address, string policy)
    {
        Validate(policy);
        if (IPAddress.TryParse(address, out var ip) && Strict(policy) && (ip.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4") != policy)
            throw new OperationException("明确 IP 与下一跳连接地址族冲突；不会改写 IP 或换到其他代理。");
    }
    public static JsonObject Direct(string policy, string tag, bool xray)
    {
        Validate(policy);
        if (!xray)
        {
            var output = new JsonObject { ["type"] = "direct", ["tag"] = tag };
            ApplySing(output, policy); return output;
        }
        var value = new JsonObject { ["tag"] = tag, ["protocol"] = "freedom", ["settings"] = new JsonObject { ["domainStrategy"] = policy switch { "IPv4" => "ForceIPv4", "IPv6" => "ForceIPv6", _ => "AsIs" } } };
        if (policy is "PreferIPv4" or "PreferIPv6") ApplyXray(value, policy);
        return value;
    }
    public static void ApplySing(JsonObject output, string policy)
    {
        Validate(policy);
        if (output.Text("server") != "") Endpoint(output.Text("server"), policy);
        if (output.ContainsKey("domain_resolver") || output.ContainsKey("domain_strategy") || output.ContainsKey("fallback_delay")) throw new OperationException("来源已有拨号地址族策略，不静默覆盖。");
        output["domain_resolver"] = new JsonObject { ["server"] = "local", ["strategy"] = SingStrategy(policy) };
        if (policy is "PreferIPv4" or "PreferIPv6") output["fallback_delay"] = "300ms";
    }
    public static void ApplyXray(JsonObject output, string policy)
    {
        Validate(policy); if (policy == "Auto") return;
        output["streamSettings"] ??= new JsonObject(); var stream = output["streamSettings"]!.AsObject();
        Set(stream);
        if (stream.At("xhttpSettings.extra.downloadSettings") is JsonObject download) Set(download);
        void Set(JsonObject settings)
        {
            settings["sockopt"] ??= new JsonObject(); var options = settings["sockopt"]!.AsObject();
            if (options.ContainsKey("domainStrategy") || options.ContainsKey("happyEyeballs")) throw new OperationException("来源已有拨号地址族策略，不静默覆盖。");
            options["domainStrategy"] = policy switch { "IPv4" => "ForceIPv4", "IPv6" => "ForceIPv6", _ => "ForceIP" };
            if (policy is "PreferIPv4" or "PreferIPv6") options["happyEyeballs"] = new JsonObject { ["prioritizeIPv6"] = policy == "PreferIPv6", ["tryDelayMs"] = 300, ["interleave"] = 1, ["maxConcurrentTry"] = 2 };
        }
    }
    public static JsonObject Configure(JsonObject configuration, JsonObject model, JsonObject inbound)
    {
        var xray = InboundCatalog.UsesXray(inbound);
        foreach (var target in InboundCatalog.Items(model, "Outbounds").Where(o => o.Text("Kind") == "Proxy" && InboundRoutingPolicy.References(inbound).Contains(o.Text("Id"))))
        {
            var policy = target.Text("ConnectionFamily", "Auto"); if (policy == "Auto") continue;
            var native = configuration["outbounds"]!.AsArray().OfType<JsonObject>().Single(o => o.Text("tag") == InboundRoutingPolicy.Tag(inbound, target.Text("Id")));
            if (xray) ApplyXray(native, policy); else ApplySing(native, policy);
        }
        if (xray && configuration["outbounds"]!.AsArray().Any(o => o!.At("streamSettings.sockopt") != null))
            configuration["dns"] = new JsonObject { ["servers"] = new JsonArray("localhost"), ["queryStrategy"] = "UseIP" };
        return configuration;
    }
}
