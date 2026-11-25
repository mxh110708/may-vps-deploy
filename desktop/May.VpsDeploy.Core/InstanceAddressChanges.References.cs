using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class InstanceAddressChanges
{
    internal static void CompleteReferences(ArchiveStore store, JsonObject document, (string RelativePath, JsonObject Plan)[] instances)
    {
        var scratch = store.Paths.Resolve("private/address-previews/" + Guid.NewGuid().ToString("N"));
        var stage = store.WithPrivateRoot(scratch); var map = document["Addresses"]!.AsObject();
        var originals = new Dictionary<string, (JsonObject Value, bool Secret)>();
        var hosts = document["Hosts"]!.AsArray(); var files = document["Files"]!.AsArray();
        void Copy(string relative, bool secret)
        {
            var from = SafePath.Resolve(store.Paths.Private, relative); if (!File.Exists(from)) return;
            var before = secret ? store.ReadSecret(from) : ArchiveStore.ReadJson(from);
            var next = files.OfType<JsonObject>().SingleOrDefault(f => f.Text("Path") == relative)?["After"]?.DeepClone().AsObject() ?? before.DeepClone().AsObject();
            if (relative.Contains("/server-configs/", StringComparison.Ordinal)) Rewrite(next, map);
            originals[relative] = (before, secret);
            var target = SafePath.Resolve(scratch, relative);
            if (secret) stage.WriteSecret(target, next); else ArchiveStore.WriteJson(target, next);
        }
        try
        {
            Directory.CreateDirectory(scratch);
            foreach (var instance in instances)
            {
                var root = "instances/" + instance.RelativePath + "/";
                foreach (var name in new[] { "deployment-plan.json", "deployment-state.json" }) Copy(root + name, false);
                Copy(root + "secrets.dotnet.private.json", true);
                foreach (var (_, name) in ProtocolFiles) Copy(root + "server-configs/" + name, false);
                var host = hosts.OfType<JsonObject>().SingleOrDefault(h => h.Text("Instance") == instance.RelativePath);
                if (host != null) ArchiveStore.WriteJson(SafePath.Resolve(stage.Paths.Instance(instance.RelativePath), "deployment-plan.json"), host["After"]!);
                if (host != null)
                {
                    var projected = host["ProjectedHashes"] as JsonObject ?? new JsonObject();
                    var statePath = SafePath.Resolve(stage.Paths.Instance(instance.RelativePath), "deployment-state.json"); var shadowState = ArchiveStore.ReadJson(statePath);
                    foreach (var component in WireGuardTunnels.Components.Where(c => host["After"]![c] != null))
                    {
                        if (projected[component] != null) shadowState.Put(component + ".RemoteHash", projected[component]!.DeepClone());
                        shadowState.Put(component + ".ConfigurationFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(host["After"]![component]!)));
                    }
                    ArchiveStore.WriteJson(statePath, shadowState);
                }
            }
            foreach (var folder in new[] { "client-schemes", "client-node-groups", "tcp-chains", "wireguard-tunnels" })
            {
                var dir = store.Paths.Resolve("private/" + folder); if (!Directory.Exists(dir)) continue; SafePath.CheckTree(dir);
                foreach (var file in Directory.EnumerateFiles(dir, "*.json")) Copy(folder + "/" + Path.GetFileName(file), folder.StartsWith("client-", StringComparison.Ordinal));
            }
            Preparing.Value = true;
            for (var pass = 0; pass < 16; pass++)
            {
                var beforePass = originals.ToDictionary(p => p.Key, p => Read(p.Key, p.Value.Secret));
                var affected = instances.Where(i => !JsonNode.DeepEquals(i.Plan, Read("instances/" + i.RelativePath + "/deployment-plan.json", false))).Select(i => i.RelativePath).Concat(hosts.Select(h => h!.Text("Instance"))).ToHashSet(StringComparer.Ordinal);
                foreach (var entry in originals.Where(p => p.Key.StartsWith("tcp-chains/", StringComparison.Ordinal)))
                {
                    var chain = Read(entry.Key, false); var configuration = chain["Configuration"]!.AsObject();
                    if (chain.Text("Phase") != "Active" || !TcpChains.Instances(configuration).Any(affected.Contains)) continue;
                    foreach (var reference in TcpChainUnderlay.References(configuration))
                    {
                        var tunnel = Read("wireguard-tunnels/" + reference.Text("Id") + ".json", false);
                        reference["Fingerprint"] = TcpChainUnderlay.Reference(stage, tunnel, reference.Text("Segment"))["Fingerprint"]!.DeepClone();
                    }
                    Write(entry.Key, chain, false);
                }
                foreach (var entry in originals.Where(p => p.Value.Secret && p.Key.StartsWith("client-", StringComparison.Ordinal)))
                {
                    var value = Read(entry.Key, true);
                    foreach (var node in (value["Nodes"] as JsonArray ?? []).OfType<JsonObject>())
                    {
                        var origin = (node["ForwardedOrigin"] ?? node["ManagedOrigin"] ?? node["InboundOrigin"]) as JsonObject;
                        if (origin != null && affected.Contains(origin.Text("Instance")))
                        {
                            var instance = origin.Text("Instance"); var plan = TcpChains.Plan(stage, instance);
                            var secret = stage.ReadSecret(SafePath.Resolve(stage.Paths.Instance(instance), "secrets.dotnet.private.json"));
                            try
                            {
                                if (node["ForwardedOrigin"] != null)
                                {
                                    if (pass == 0) ForwardedNodeSources.VerifyNodes(store, [(entry.Value.Value["Nodes"] as JsonArray ?? []).OfType<JsonObject>().Single(n => n.Text("Id") == node.Text("Id"))]);
                                    var rule = TcpForwarding.Rules(plan["TcpForwarding"] as JsonObject).Single(r => r.Text("Id") == origin.Text("RuleId"));
                                    var clean = rule.DeepClone().AsObject(); clean.Remove("Name"); origin["TcpFingerprint"] = ArchiveStore.Fingerprint(clean);
                                    if (origin.Text("UdpRuleId") != "") { var udp = UdpForwarding.Rules(plan["UdpForwarding"] as JsonObject).Single(r => r.Text("Id") == origin.Text("UdpRuleId")).DeepClone().AsObject(); udp.Remove("Name"); origin["UdpFingerprint"] = ArchiveStore.Fingerprint(udp); }
                                    origin["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node);
                                }
                                else if (node["ManagedOrigin"] != null)
                                {
                                    if (pass == 0)
                                    {
                                        var originalNode = (entry.Value.Value["Nodes"] as JsonArray ?? []).OfType<JsonObject>().Single(n => n.Text("Id") == node.Text("Id"));
                                        ManagedNodeSources.Verify(store, new JsonArray(originalNode["ManagedOrigin"]!.DeepClone()));
                                        var oldPlan = TcpChains.Plan(store, instance); var oldSecret = store.ReadSecret(SafePath.Resolve(store.Paths.Instance(instance), "secrets.dotnet.private.json"));
                                        try
                                        {
                                            var originalPair = ManagedNodeSources.Resolve(originalNode["ManagedOrigin"]!.AsObject(), oldPlan, oldSecret) ?? throw new OperationException("原受管来源已失效。");
                                            var canonical = originalNode.DeepClone().AsObject(); canonical["clash"] = originalPair.Clash.DeepClone(); canonical["sing_box"] = originalPair.SingBox.DeepClone();
                                            if (ClientNodeImport.ConnectionFingerprint(canonical) != ClientNodeImport.ConnectionFingerprint(originalNode)) throw new OperationException("受管节点含本地连接修改，先更新或解除来源，换址不会替换其凭据。");
                                        }
                                        finally { oldSecret.Clear(); }
                                    }
                                    var pair = ManagedNodeSources.Resolve(origin, plan, secret) ?? throw new OperationException("受影响节点已不属于当前受管实例。");
                                    node["clash"] = pair.Clash.DeepClone(); node["sing_box"] = pair.SingBox.DeepClone(); node["clash"]!["name"] = node.Text("name"); node["sing_box"]!["tag"] = node.Text("name");
                                    node["ManagedOrigin"] = ManagedNodeSources.Origin(instance, pair);
                                }
                                else if (node["InboundOrigin"] != null)
                                {
                                    if (pass == 0) { var originalNode = (entry.Value.Value["Nodes"] as JsonArray ?? []).OfType<JsonObject>().Single(n => n.Text("Id") == node.Text("Id")); var preparing = Preparing.Value; Preparing.Value = false; try { InboundSources.VerifyNodes(store, [originalNode]); } finally { Preparing.Value = preparing; } }
                                    var current = InboundSources.Create(stage, instance, origin.Text("InboundId"), origin.Text("UserId"), origin.Text("Family"));
                                    foreach (var key in new[] { "clash", "sing_box", "InboundOrigin" }) node[key] = current[key]?.DeepClone();
                                    if (node["clash"] != null) node["clash"]!["name"] = node.Text("name"); if (node["sing_box"] != null) node["sing_box"]!["tag"] = node.Text("name");
                                }
                            }
                            finally { secret.Clear(); }
                        }
                        if (node["TcpChainOrigin"] is JsonObject chain)
                        {
                            if (pass == 0) TcpChains.VerifyNodes(store, [(entry.Value.Value["Nodes"] as JsonArray ?? []).OfType<JsonObject>().Single(n => n.Text("Id") == node.Text("Id"))]);
                            var record = Read("tcp-chains/" + TcpChains.Id(chain.Text("Id")) + ".json", false);
                            chain["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(record["Configuration"]!); chain["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node);
                        }
                        if (node["GroupOrigin"] is JsonObject groupOrigin) groupOrigin["MemberFingerprint"] = ClientNodeGroups.MemberFingerprint(node);
                    }
                    if (!JsonNode.DeepEquals(value, entry.Value.Value)) value.Remove("Candidate"); Write(entry.Key, value, true);
                }
                var replacements = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var entry in originals) { var current = Read(entry.Key, entry.Value.Secret); Collect(entry.Value.Value, current, replacements); Collect(beforePass[entry.Key], current, replacements); }
                foreach (var entry in originals)
                {
                    if (entry.Key.Contains("/server-configs/", StringComparison.Ordinal) || entry.Key.EndsWith("/deployment-state.json", StringComparison.Ordinal) || entry.Key.EndsWith("/secrets.dotnet.private.json", StringComparison.Ordinal)) continue;
                    var value = Read(entry.Key, entry.Value.Secret); ReplaceFingerprints(value, replacements); Write(entry.Key, value, entry.Value.Secret);
                }
                if (originals.All(e => JsonNode.DeepEquals(beforePass[e.Key], Read(e.Key, e.Value.Secret)))) break;
                if (pass == 15) throw new OperationException("来源依赖无法收敛，请先简化循环引用。");
            }
            foreach (var instance in instances)
            {
                var prefix = "instances/" + instance.RelativePath + "/";
                var after = Read(prefix + "deployment-plan.json", false);
                var configChanged = ProtocolFiles.Any(p => originals.ContainsKey(prefix + "server-configs/" + p.File) && !JsonNode.DeepEquals(originals[prefix + "server-configs/" + p.File].Value, Read(prefix + "server-configs/" + p.File, false)));
                if (JsonNode.DeepEquals(instance.Plan, after) && !configChanged) continue;
                var host = hosts.OfType<JsonObject>().SingleOrDefault(h => h.Text("Instance") == instance.RelativePath);
                var state = originals[prefix + "deployment-state.json"].Value;
                if (InstanceLifecycle.Read(store, instance.RelativePath, instance.Plan).NeedsRecovery) throw new OperationException("受影响来源存在待恢复事务。");
                if (host == null)
                {
                    host = new JsonObject { ["Instance"] = instance.RelativePath, ["Before"] = instance.Plan.DeepClone(), ["State"] = state.DeepClone(), ["Pin"] = Pin(store, instance.Plan.Text("Server.IPv4")), ["Hashes"] = new JsonObject { ["Plan"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Private, prefix + "deployment-plan.json")), ["State"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Private, prefix + "deployment-state.json")), ["Secrets"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Private, prefix + "secrets.dotnet.private.json")) } }; hosts.Add(host);
                }
                host["After"] = after.DeepClone(); var resources = new JsonArray(); host["Resources"] = resources;
                void Add(string kind, JsonNode before, JsonNode next, string expected) => resources.Add(new JsonObject { ["Kind"] = kind, ["Component"] = kind, ["ExpectedHash"] = expected, ["Before"] = before.DeepClone(), ["After"] = next.DeepClone() });
                foreach (var component in new[] { "TcpForwarding", "UdpForwarding", "WireGuardTunnel", "WireGuardTunnel2" })
                    if (instance.Plan[component] != null && !JsonNode.DeepEquals(instance.Plan[component], after[component]))
                    {
                        Add(component, instance.Plan[component]!, after[component]!, state.Text(component + ".RemoteHash"));
                        if (component is "TcpForwarding" or "UdpForwarding" && TcpForwarding.Rules(after[component]!.AsObject()).Any(ForwardProxyHealth.Selected)) resources[^1]!["AfterProbeHealth"] = ForwardProxyHealth.Document(stage, after[component]!.AsObject());
                    }
                foreach (var (role, name) in ProtocolFiles)
                {
                    var path = prefix + "server-configs/" + name; if (!originals.TryGetValue(path, out var entry)) continue; var next = Read(path, false);
                    if (!JsonNode.DeepEquals(entry.Value, next)) Add(role, entry.Value, next, state.Text("ServerConfigHashes." + role));
                }
                if (instance.Plan["InboundModel"] is JsonObject model && InboundCatalog.Items(model, "Inbounds").Any() && (!JsonNode.DeepEquals(model, after["InboundModel"]) || instance.RelativePath == document.Text("Instance")))
                {
                    Add("Inbounds", model, after["InboundModel"]!, state.Text("Inbounds.RemoteHash"));
                    var credentials = stage.ReadSecret(SafePath.Resolve(stage.Paths.Instance(instance.RelativePath), "secrets.dotnet.private.json"));
                    try { resources[^1]!["AfterPayload"] = InboundRendering.Payload(stage, after, after["InboundModel"]!.AsObject(), credentials["Inbounds"]!.AsObject(), state.At("Inbounds.Core") as JsonObject); }
                    finally { credentials.Clear(); }
                }
                var fw = !JsonNode.DeepEquals(instance.Plan["Shadowsocks"], after["Shadowsocks"]) || WireGuardTunnels.Components.Any(c => !JsonNode.DeepEquals(instance.Plan[c], after[c]));
                if (fw && instance.Plan.Text("Firewall.Mode") != "PreserveExisting") Add("Firewall", new JsonObject(), new JsonObject(), "Managed");
                if (resources.OfType<JsonObject>().Any(r => r.Text("ExpectedHash") is "" or "Absent")) throw new OperationException("受影响组件缺少已核对的远端归属摘要。");
            }
            // Lock and validate the complete connected topology, including a
            // participant whose own address and configuration remain unchanged.
            var topology = originals.Where(p => p.Key.StartsWith("tcp-chains/", StringComparison.Ordinal) || p.Key.StartsWith("wireguard-tunnels/", StringComparison.Ordinal)).ToArray();
            void AddParticipant(string participant)
            {
                if (hosts.Any(h => h!.Text("Instance") == participant)) return;
                var original = instances.Single(i => i.RelativePath == participant).Plan; var dir = store.Paths.Instance(participant);
                if (InstanceLifecycle.Read(store, participant, original).NeedsRecovery) throw new OperationException("线路参与实例存在待恢复事务。");
                var resources = new JsonArray();
                if (original["InboundModel"] is JsonObject model && InboundCatalog.Items(model, "Inbounds").Any())
                {
                    var state = originals["instances/" + participant + "/deployment-state.json"].Value; var credentials = stage.ReadSecret(SafePath.Resolve(stage.Paths.Instance(participant), "secrets.dotnet.private.json"));
                    try { resources.Add(new JsonObject { ["Kind"] = "Inbounds", ["Component"] = "Inbounds", ["ExpectedHash"] = state.Text("Inbounds.RemoteHash"), ["Before"] = model.DeepClone(), ["After"] = model.DeepClone(), ["AfterPayload"] = InboundRendering.Payload(stage, original, model, credentials["Inbounds"]!.AsObject(), state.At("Inbounds.Core") as JsonObject) }); }
                    finally { credentials.Clear(); }
                }
                hosts.Add(new JsonObject { ["Instance"] = participant, ["Before"] = original.DeepClone(), ["After"] = original.DeepClone(), ["State"] = originals["instances/" + participant + "/deployment-state.json"].Value.DeepClone(), ["Pin"] = Pin(store, original.Text("Server.IPv4")), ["Resources"] = resources, ["Hashes"] = new JsonObject { ["Plan"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(dir, "deployment-plan.json")), ["State"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(dir, "deployment-state.json")), ["Secrets"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(dir, "secrets.dotnet.private.json")) } });
            }
            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var entry in topology)
                {
                    var value = Read(entry.Key, false); var config = value["Configuration"]!.AsObject();
                    var participants = entry.Key.StartsWith("tcp-", StringComparison.Ordinal) ? TcpChains.Instances(config) : WireGuardTunnels.Instances(config);
                    if (!participants.Any(i => hosts.Any(h => h!.Text("Instance") == i))) continue;
                    if (value.Text("Phase") is not ("Active" or "Removed" or "RolledBack")) throw new OperationException("相关线路或隧道有未完成事务，请先恢复。");
                    if (value.Text("Phase") != "Active") continue;
                    foreach (var participant in participants.Where(i => !hosts.Any(h => h!.Text("Instance") == i)))
                    {
                        AddParticipant(participant); changed = true;
                    }
                }
                var dependentNodes = new HashSet<string>(StringComparer.Ordinal);
                foreach (var entry in originals.Where(e => e.Key.StartsWith("client-schemes/", StringComparison.Ordinal)))
                {
                    var value = Read(entry.Key, true);
                    foreach (var node in (value["Nodes"] as JsonArray ?? []).OfType<JsonObject>())
                    {
                        var origin = (node["ManagedOrigin"] ?? node["InboundOrigin"] ?? node["ForwardedOrigin"]) as JsonObject;
                        var connectedChain = node.Text("TcpChainOrigin.Id") != "" && topology.Any(t => t.Key == "tcp-chains/" + node.Text("TcpChainOrigin.Id") + ".json" && TcpChains.Instances(t.Value.Value["Configuration"]!.AsObject()).Any(i => hosts.Any(h => h!.Text("Instance") == i)));
                        if (origin != null && hosts.Any(h => h!.Text("Instance") == origin.Text("Instance")) || connectedChain) dependentNodes.Add(value.Text("Id") + ":" + node.Text("Id"));
                    }
                }
                bool Depends(JsonNode? n)
                {
                    if (n is JsonObject o) return dependentNodes.Contains(o.Text("SchemeId") + ":" + o.Text("NodeId")) || o.Any(p => Depends(p.Value));
                    return n is JsonArray a && a.Any(Depends);
                }
                foreach (var instance in instances.Where(i => !hosts.Any(h => h!.Text("Instance") == i.RelativePath) && Depends(i.Plan))) { AddParticipant(instance.RelativePath); changed = true; }
            }
            files.Clear();
            foreach (var entry in originals)
            {
                if (entry.Key.EndsWith("/deployment-plan.json", StringComparison.Ordinal) || entry.Key.EndsWith("/deployment-state.json", StringComparison.Ordinal) || entry.Key.EndsWith("/secrets.dotnet.private.json", StringComparison.Ordinal)) continue;
                var after = Read(entry.Key, entry.Value.Secret);
                var connected = topology.Any(t => t.Key == entry.Key) && after.Text("Phase") == "Active" && (entry.Key.StartsWith("tcp-", StringComparison.Ordinal) ? TcpChains.Instances(after["Configuration"]!.AsObject()) : WireGuardTunnels.Instances(after["Configuration"]!.AsObject())).Any(i => hosts.Any(h => h!.Text("Instance") == i));
                var potentialSource = entry.Key.StartsWith("client-", StringComparison.Ordinal) && (after["Nodes"] as JsonArray ?? []).OfType<JsonObject>().Any(n => n["TcpChainOrigin"] != null || hosts.Any(h => h!.Text("Instance") == n.Text("ManagedOrigin.Instance", n.Text("InboundOrigin.Instance", n.Text("ForwardedOrigin.Instance")))));
                if (JsonNode.DeepEquals(entry.Value.Value, after) && !connected && !potentialSource) continue;
                files.Add(new JsonObject { ["Path"] = entry.Key, ["Secret"] = entry.Value.Secret, ["Before"] = entry.Value.Value.DeepClone(), ["After"] = after, ["Hash"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Private, entry.Key)) });
            }
            JsonObject Read(string path, bool secret) => secret ? stage.ReadSecret(SafePath.Resolve(scratch, path)) : ArchiveStore.ReadJson(SafePath.Resolve(scratch, path));
            void Write(string path, JsonObject value, bool secret) { if (secret) stage.WriteSecret(SafePath.Resolve(scratch, path), value); else ArchiveStore.WriteJson(SafePath.Resolve(scratch, path), value); }
        }
        finally { Preparing.Value = false; if (Directory.Exists(scratch)) { SafePath.CheckTree(scratch); Directory.Delete(scratch, true); } }
    }
    private static void Collect(JsonNode? before, JsonNode? after, Dictionary<string, string> hashes)
    {
        if (before == null || after == null || JsonNode.DeepEquals(before, after)) return;
        if (before is JsonObject a && after is JsonObject b) { hashes[ArchiveStore.Fingerprint(a)] = ArchiveStore.Fingerprint(b); foreach (var (key, value) in a) if (b.ContainsKey(key)) Collect(value, b[key], hashes); }
        else if (before is JsonArray x && after is JsonArray y && x.Count == y.Count) { hashes[ArchiveStore.Fingerprint(x)] = ArchiveStore.Fingerprint(y); for (var i = 0; i < x.Count; i++) Collect(x[i], y[i], hashes); }
    }
    private static void ReplaceFingerprints(JsonNode node, Dictionary<string, string> hashes)
    {
        if (node is JsonObject o) foreach (var (key, value) in o.ToArray())
        {
            if ((key.EndsWith("Fingerprint", StringComparison.Ordinal) || key is "ClientSha256" or "Revision") && value is JsonValue v && v.TryGetValue<string>(out var text) && hashes.TryGetValue(text, out var next)) o[key] = next;
            else if (value is JsonObject or JsonArray) ReplaceFingerprints(value, hashes);
        }
        else if (node is JsonArray a) foreach (var value in a.Where(n => n != null)) ReplaceFingerprints(value!, hashes);
    }
}
