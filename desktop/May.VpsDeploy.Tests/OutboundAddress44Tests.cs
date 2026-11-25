using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public static void Address44Fixtures()
    {
        var values = new JsonObject();
        foreach (var policy in OutboundAddressPolicy.Values)
        {
            var sing = OutboundAddressPolicy.Direct(policy, "egress", false); var xray = OutboundAddressPolicy.Direct(policy, "egress", true);
            var proxy = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "egress", ["server"] = "family.example.test", ["server_port"] = 1, ["method"] = "aes-128-gcm", ["password"] = "synthetic-address44-password" };
            var proxyXray = ServerOutboundRouting.XrayNextHop(proxy); var proxySing = proxy.DeepClone().AsObject();
            if (policy != "Auto") { OutboundAddressPolicy.ApplySing(proxySing, policy); OutboundAddressPolicy.ApplyXray(proxyXray, policy); }
            values[policy] = new JsonObject { ["sing-box"] = sing, ["xray"] = xray, ["sing-box-proxy"] = proxySing, ["xray-proxy"] = proxyXray };
        }
        Console.WriteLine(values.ToJsonString());
    }
    public async Task RunOutboundAddress44Tests()
    {
        await Task.CompletedTask;
        foreach (var policy in OutboundAddressPolicy.Values)
        {
            var sing = OutboundAddressPolicy.Direct(policy, "egress", false); var xray = OutboundAddressPolicy.Direct(policy, "egress", true);
            Check(sing.Text("domain_resolver.strategy") == OutboundAddressPolicy.SingStrategy(policy), "direct resolver not bound to address policy");
            if (policy is "PreferIPv4" or "PreferIPv6")
            {
                Check(sing.Text("fallback_delay") == "300ms" && xray.Number("streamSettings.sockopt.happyEyeballs.tryDelayMs") == 300, "DNS preference mistaken for connection fallback");
                Check(xray.Flag("streamSettings.sockopt.happyEyeballs.prioritizeIPv6") == (policy == "PreferIPv6") && xray.Text("settings.domainStrategy") == "AsIs", "Xray freedom discarded second family before racing");
            }
            Check(OutboundAddressPolicy.ObservedFamily(policy) == (OutboundAddressPolicy.Strict(policy) ? policy : "Auto"), "preference treated as observed final egress family");
            OutboundAddressPolicy.Endpoint("192.0.2.44", policy == "IPv6" ? "Auto" : policy);
        }
        Refuses(() => OutboundAddressPolicy.Endpoint("192.0.2.44", "IPv6"), "explicit IPv4 crossed strict IPv6 policy");
        Refuses(() => OutboundAddressPolicy.Endpoint("2001:db8::44", "IPv4"), "explicit IPv6 crossed strict IPv4 policy");
        Refuses(() => OutboundAddressPolicy.Validate("whatever"), "unknown family accepted");
        var native = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "egress", ["server"] = "dual.example.test", ["server_port"] = 443, ["method"] = "aes-128-gcm", ["password"] = "synthetic-password" };
        var previous = native.DeepClone(); OutboundAddressPolicy.ApplySing(native, "PreferIPv6");
        Check(native.Text("server") == previous.Text("server") && native.Text("password") == previous.Text("password"), "connection family changed proxy identity");
        var options = new JsonObject { ["tag"] = "egress", ["protocol"] = "shadowsocks", ["settings"] = new JsonObject() }; OutboundAddressPolicy.ApplyXray(options, "PreferIPv4"); Refuses(() => OutboundAddressPolicy.ApplyXray(options, "PreferIPv6"), "existing sockopt overwritten");
        using var f = new Fixture(repository); var model = InboundCatalog.Empty(); var creds = InboundCatalog.EmptyCredentials(); var outbound = InboundCatalog.AddDirect(model, "Dual egress", "PreferIPv6");
        var input = InboundCatalog.AddInbound(model, creds, "Shadowsocks2022"); input["OutboundId"] = outbound.Text("Id");
        var plan = f.Plan("address44");
        plan["Server"]!["IPv6"] = "2001:db8::44";
        var pair = new ClientProfiles.NodePair("Synthetic", "RealityEntry", "IPv4", new(), new(), "Unknown");
        ProtocolValidation.RequireEgress(plan, pair, plan.Text("Server.IPv4")); Check(true, "unknown policy rejected valid observed IPv4");
        ProtocolValidation.RequireEgress(plan, pair, "2001:db8::44"); Check(true, "IPv6 observed egress compared against IPv4 plan");
        Refuses(() => ProtocolValidation.RequireEgress(plan, pair with { EgressFamily = "IPv4" }, "2001:db8::44"), "strict IPv4 accepted IPv6 egress");
        Refuses(() => ProtocolValidation.RequireEgress(plan, pair, "2001:db8::45"), "known planned IPv6 identity ignored");
        plan["Server"]!.AsObject().Remove("IPv6"); ProtocolValidation.RequireEgress(plan, pair, "2001:db8::44"); Check(true, "observed optional IPv6 was mistaken for verified IPv4");
        plan["ServerOutbound"] = new JsonObject { ["RealityEntry"] = new JsonObject { ["ExpectedAddress"] = "198.51.100.44" } };
        ProtocolValidation.RequireEgress(plan, pair, "198.51.100.44"); Check(true, "fixed landing endpoint compared against entry egress");
        Refuses(() => ProtocolValidation.RequireEgress(plan, pair, plan.Text("Server.IPv4")), "proxy endpoint family bypassed final landing verification");
        plan.Remove("ServerOutbound");
        var config = InboundRendering.Configuration(f.Store, plan, model, creds, input);
        Check(config["route"]!["rules"]!.AsArray().Count == 0 && config.Text("outbounds.0") == "", "preferred family accidentally blocked explicit opposite-family IP");
        Check(config["outbounds"]![0]!.Text("domain_resolver.strategy") == "prefer_ipv6", "preference not applied through product renderer");
        var payload = InboundRendering.Payload(f.Store, plan, model, creds); var oldHash = payload["Bindings"]?.ToJsonString() ?? payload.ToJsonString();
        outbound["Family"] = "PreferIPv4"; var newPayload = InboundRendering.Payload(f.Store, plan, model, creds);
        Check(oldHash != (newPayload["Bindings"]?.ToJsonString() ?? newPayload.ToJsonString()), "family change did not invalidate config identity");
        Console.WriteLine($"PASS: {assertions} direct, next-hop, DNS, explicit IP, immutable identity and family policy assertions.");
    }
}
