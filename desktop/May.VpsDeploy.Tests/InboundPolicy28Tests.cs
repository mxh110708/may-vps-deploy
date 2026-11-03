using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunInboundPolicy28Tests(bool modelOnly = false)
    {
        await InboundPolicy28Model();
        if (!modelOnly) { await InboundPolicy28Runtime(); await InboundPolicy28ProbeRuntime(); }
        Console.WriteLine($"PASS: {assertions} round-28 independent policy, provenance, real paths and scoped recovery assertions; modelOnly={modelOnly}.");
    }
    private static JsonObject Policy28Proof(JsonObject request)
    {
        return new JsonObject { ["InboundId"] = request.Text("InboundId"), ["ConfigurationSha256"] = request.Text("ConfigurationSha256"), ["PolicyFingerprint"] = request.Text("PolicyFingerprint"), ["Status"] = "Passed", ["Items"] = new JsonArray(request["Paths"]!.AsArray().Select(p => (JsonNode?)new JsonObject
        {
            ["Id"] = p!.Text("Id"), ["OutboundFingerprint"] = p.Text("OutboundFingerprint"), ["Status"] = "Passed", ["From"] = "EntryServer", ["Scope"] = "NativeOutboundHttps", ["Network"] = "TCP", ["Egress"] = p.Text("ExpectedAddress") != "" ? p.Text("ExpectedAddress") : p.Text("Family") == "IPv6" ? "2001:db8::28" : "198.51.100.28"
        }).ToArray()) };
    }
    private static (JsonObject Resource, JsonObject Scheme, JsonObject Node) Policy28Exit(Fixture f, JsonObject model, string name, string host = "192.0.2.28", int port = 33443)
    {
        var scheme = ClientSchemes.New(f.Paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
        var native = new JsonObject { ["type"] = "shadowsocks", ["tag"] = name, ["server"] = host, ["server_port"] = port, ["method"] = "chacha20-ietf-poly1305", ["password"] = ServerConfigurations.RandomKey(32) };
        var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = name, ["kind"] = "entry", ["region_group"] = region, ["transit_group"] = region, ["sing_box"] = native, ["clash"] = new JsonObject { ["name"] = name, ["type"] = "ss", ["server"] = host, ["port"] = port, ["cipher"] = native.Text("method"), ["password"] = native.Text("password") } };
        scheme["Nodes"]!.AsArray().Add(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var resource = InboundCatalog.AddDirect(model, name); resource["Kind"] = "Proxy";
        resource["Source"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(node) };
        return (resource, scheme, node);
    }
    private async Task InboundPolicy28Model()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Policy28"); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
        var (model, secrets) = InboundModel(); var first = InboundCatalog.Items(model, "Inbounds").First(); var second = InboundCatalog.Items(model, "Inbounds").Last();
        var baseline = InboundRendering.Payload(f.Store, plan, model, secrets); var noRules = model.DeepClone().AsObject(); noRules["Inbounds"]![0]!["Routing"] = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray() };
        var clean = InboundCatalog.Normalize(noRules, secrets); Check(JsonNode.DeepEquals(clean, model) && JsonNode.DeepEquals(baseline, InboundRendering.Payload(f.Store, plan, clean, secrets)), "opening an empty policy changed existing configuration or identity");
        var extra = Policy28Exit(f, model, "additional exit");
        var category = ServerRuleSets.Normalize(new JsonObject { ["Schema"] = 1, ["Id"] = "policy28-category", ["Name"] = "Policy28 category", ["Revision"] = "1.0.0", ["Rules"] = new JsonArray(new JsonObject { ["Kind"] = "Suffix", ["Value"] = "research.example.test" }) });
        var policy = new JsonArray(new JsonObject { ["Kind"] = "RuleSet", ["Value"] = category.Text("Id"), ["Action"] = "NextHop", ["Target"] = extra.Resource.Text("Id"), ["RuleSet"] = category.DeepClone() }, DestinationRule("Domain", "campus.example.test", "Direct"), DestinationRule("Cidr", "203.0.113.0/24", "Reject"));
        InboundRoutingPolicy.Set(first, policy); _ = InboundCatalog.Normalize(model, secrets);
        var config = InboundRendering.Configuration(f.Store, plan, model, secrets, first);
        Check(config["route"]!["rules"]![0]!.Text("network") == "tcp" && config.Text("route.final") == "egress", "policy altered application UDP/default route");
        Check(config["route"]!["rules"]![0]!.Text("outbound") == "policy-" + extra.Resource.Text("Id") && config["outbounds"]!.AsArray().Count == 3, "policy did not bind the named outbound resource");
        Refuses(() => InboundCatalog.RemoveEntity(model, secrets, "Outbounds", extra.Resource.Text("Id")), "TCP-only policy dependency could be deleted");
        Check(InboundRendering.RequiresApplicationUdp(f.Store, f.Relative(plan), model, first.Text("Id")), "policy default UDP validation was optional");
        var summary = InboundRoutingPolicy.Summary(model, first); Check(summary.Contains("1.0.0") && summary.Contains("additional exit") && !summary.Contains(extra.Node.Text("sing_box.password")), "policy review omitted pinned version or exposed authentication");
        var malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Version"] = 2; Refuses(() => InboundCatalog.Normalize(malformed, secrets), "unknown policy version accepted");
        malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Network"] = "udp"; Refuses(() => InboundCatalog.Normalize(malformed, secrets), "unimplemented UDP classification accepted");
        malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Rules"]![0]!["Target"] = Guid.NewGuid().ToString("N"); Refuses(() => InboundCatalog.Normalize(malformed, secrets), "missing policy resource fell back to default");
        malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Rules"]![0]!["RuleSet"]!["Rules"]![0]!["Command"] = "ignored"; Refuses(() => InboundCatalog.Normalize(malformed, secrets), "category accepted executable or unknown fields");
        malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Rules"]!.AsArray().Insert(0, DestinationRule("Suffix", "ipify.org", "Direct")); Refuses(() => InboundCatalog.Normalize(malformed, secrets), "policy bypassed its default-path acceptance");
        malformed = model.DeepClone().AsObject(); malformed["Inbounds"]![0]!["Routing"]!["Rules"]!.AsArray().Add(DestinationRule("Cidr", "2001:db8::/32", "Direct")); Refuses(() => InboundCatalog.Normalize(malformed, secrets), "IPv6 exception accepted on an IPv4-only direct path");
        var request = InboundRoutingPolicy.ProbeRequest(f.Store, plan, model, secrets, first); var proof = Policy28Proof(request); InboundRoutingPolicy.RequirePaths(request, proof); Check(proof["Items"]!.AsArray().Count == 3, "native branch evidence did not include default, extra and direct");
        foreach (var damage in new[] { "missing", "duplicate", "policy", "config", "scope", "family", "network", "status", "outbound" })
        {
            var invalid = proof.DeepClone().AsObject(); var row = invalid["Items"]![0]!;
            switch (damage)
            {
                case "missing": invalid["Items"]!.AsArray().RemoveAt(0); break;
                case "duplicate": invalid["Items"]![1] = row.DeepClone(); break;
                case "policy": invalid["PolicyFingerprint"] = new string('f', 64); break;
                case "config": invalid["ConfigurationSha256"] = new string('a', 64); break;
                case "scope": row["Scope"] = "ModelOnly"; break;
                case "family": row["Egress"] = "2001:db8::28"; break;
                case "network": row["Network"] = "UDP"; break;
                case "status": row["Status"] = "Skipped"; break;
                case "outbound": row["OutboundFingerprint"] = new string('f', 64); break;
            }
            Refuses(() => InboundRoutingPolicy.RequirePaths(request, invalid), "policy accepted stale/partial evidence: " + damage);
        }
        // The library's new head does not rewrite the snapshot already in use.
        var before = InboundRoutingPolicy.Fingerprint(model, first); var library = new ServerRuleSetStore(f.Store); library.Apply(library.Preview(category)); category["Revision"] = "2.0.0"; category["Rules"]![0]!["Value"] = "changed.example.test"; library.Apply(library.Preview(category));
        Check(InboundRoutingPolicy.Fingerprint(model, first) == before, "rule library update changed a deployed policy snapshot");
        var statePath = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"); var state = ArchiveStore.ReadJson(statePath); var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan);
        var validator = new InboundTestValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator));
        async Task<TaskRecord> Apply(JsonObject candidate, string action = "Apply")
        {
            state = ArchiveStore.ReadJson(statePath); var operation = new OperationRequest(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(state, action, candidate, secrets));
            return await coordinator.ExecuteAsync(coordinator.Review(operation), operation, new InlineProgress<TaskProgress>(_ => { }), default);
        }
        Check((await Apply(model)).Outcome == TaskOutcome.Completed && remote.PolicyProbeCalls == 1, "new independent policy did not complete typed outbound acceptance");
        var defaultOnly = new JsonObject { ["Status"] = "Passed", ["Items"] = ArchiveStore.ReadJson(statePath)["Inbounds"]!["ValidationById"]![first.Text("Id")]!["Items"]!.DeepClone() };
        foreach (var item in defaultOnly["Items"]!.AsArray().OfType<JsonObject>()) item.Remove("PolicyValidation");
        Refuses(() => InboundSources.RequireValidation(f.Store, plan, model, secrets, [first.Text("Id")], defaultOnly), "default client-path success qualified a policy without its branch acceptance");
        var origin = InboundSources.Create(f.Store, f.Relative(plan), first.Text("Id"), first.Strings("UserIds")[0], "IPv4");
        var newer = model.DeepClone().AsObject(); newer["Inbounds"]![0]!["Routing"]!["Rules"]![0]!["RuleSet"] = category.DeepClone();
        var review = InboundCatalog.Prepare(f.Store, new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(statePath), "Apply", newer, secrets)));
        Check(review.Affected.SequenceEqual(new[] { first.Text("Id") }), "policy revision restarted an unrelated inbound"); review.Credentials.Clear();
        remote.Failure = "policy-validation"; var oldHash = ArchiveStore.Fingerprint(remote.Current!); var failed = await Apply(newer);
        Check(failed.Outcome == TaskOutcome.Failed && ArchiveStore.Fingerprint(remote.Current!) == oldHash && remote.LastAffected.SequenceEqual(new[] { first.Text("Id") }), "failed policy branch did not restore exactly the changed inbound");
        remote.Failure = ""; Check((await Apply(newer)).Outcome == TaskOutcome.Completed, "policy could not be applied after scoped recovery");
        Refuses(() => InboundSources.VerifyNodes(f.Store, [origin]), "old client origin retained qualification after a policy change");
        var fresh = InboundSources.Create(f.Store, f.Relative(plan), first.Text("Id"), first.Strings("UserIds")[0], "IPv4"); Check(ClientNodeImport.ConnectionFingerprint(fresh) == ClientNodeImport.ConnectionFingerprint(origin) && fresh.Text("InboundOrigin.ResourceFingerprint") != origin.Text("InboundOrigin.ResourceFingerprint"), "policy invalidation changed credentials or failed to change resource identity");
        extra.Node["sing_box"]!["password"] = ServerConfigurations.RandomKey(); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, extra.Scheme.Text("Id")), extra.Scheme);
        Refuses(() => coordinator.Review(new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(statePath), "Apply", newer, secrets))), "changed exception source was not rejected before writing");
        var removing = newer.DeepClone().AsObject(); InboundRoutingPolicy.Set(removing["Inbounds"]![0]!.AsObject(), new());
        Check(InboundCatalog.Prepare(f.Store, new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(statePath), "Apply", removing, secrets))).Affected.SequenceEqual(new[] { first.Text("Id") }), "removing a stale exception unnecessarily resolved its obsolete source");
        Check(InboundCatalog.Items(model, "Inbounds").Last().Text("Id") == second.Text("Id"), "policy editing changed unrelated resource identities"); secrets.Clear();
    }
}
