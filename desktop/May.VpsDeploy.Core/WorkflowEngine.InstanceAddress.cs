using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<TaskOutcome> ChangeInstanceAddress(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellation)
    {
        var preview = InstanceAddressChanges.Prepare(store, request); var document = preview.Document;
        var recovering = request.Options.Text("Action") == "Recover"; var id = recovering ? request.Options.Text("Id") : taskId;
        var recordFile = InstanceAddressChanges.RecordFile(store.Paths, id);
        var record = recovering ? store.ReadSecret(recordFile) : new JsonObject { ["Version"] = 1, ["Id"] = id, ["Instance"] = request.InstanceRelativePath, ["Document"] = document.DeepClone(), ["Phase"] = "Preparing", ["Attempted"] = new JsonArray(), ["LocalFiles"] = new JsonObject() };
        var contexts = new List<Context>(); var steps = OperationSteps.Create(request, new()); var completed = 0; string? step = null;
        var journalExists = recovering; var warned = false;
        void Save() { record["At"] = DateTimeOffset.UtcNow; store.WriteSecret(recordFile, record); journalExists = true; }
        void Begin(string name) { step = "address-" + name; progress.Report(new(taskId, step, completed, steps.Count, "正在执行换址计划。", step, TaskStepState.Running, steps)); }
        void Done() { progress.Report(new(taskId, step!, ++completed, steps.Count, "已完成。", step, TaskStepState.Completed)); }
        var previousOwner = InstanceAddressChanges.Owner.Value; InstanceAddressChanges.Owner.Value = id;
        try
        {
            foreach (var host in document["Hosts"]!.AsArray().OfType<JsonObject>())
            {
                var directory = store.Paths.Instance(host.Text("Instance"));
                var state = recovering ? ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")) : host["State"]!.DeepClone().AsObject();
                var context = new Context(this, new(OperationKind.InstanceAddress, host.Text("Instance"), new()), id, directory, host["After"]!.DeepClone().AsObject(), state,
                    store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json")), new InlineProgress<TaskProgress>(p => progress.Report(new(taskId, p.Stage, completed, steps.Count, p.Message, step))), cancellation) { HostPin = host.Text("Pin") };
                contexts.Add(context);
            }
            JsonObject Host(Context c) => document["Hosts"]!.AsArray().OfType<JsonObject>().Single(h => h.Text("Instance") == c.Request.InstanceRelativePath);
            JsonObject RemoteDocument(Context c) => new() { ["Task"] = id, ["ProgramSha256"] = document.Text("ProgramSha256"), ["Addresses"] = document["Addresses"]!.DeepClone(), ["Resources"] = Host(c)["Resources"]!.DeepClone() };
            async Task<JsonObject> Remote(Context c, string action)
            {
                async Task<JsonObject> Run(string selected)
                {
                    var response = await c.Run("instance-address.sh", new() { ["ADDRESS_ACTION"] = selected, ["ADDRESS_DOCUMENT"] = RemoteDocument(c).ToJsonString() }, selected is not ("Inspect" or "Status"), 300, "ADDRESS_OK");
                    return JsonNode.Parse(RemoteAssets.Marker(response.Output, "ADDRESS_STATE"))!.AsObject();
                }
                try { return await Run(action); }
                catch when (action is "Prepare" or "Bridge" or "Apply" or "Finalize" or "Commit")
                {
                    // An acknowledgement loss never repeats the mutation.
                    var token = c.Cancellation; c.Cancellation = CancellationToken.None;
                    try
                    {
                        var observed = await Run("Status"); var expected = action == "Prepare" ? "Prepared" : action == "Commit" ? "Committed" : action;
                        if (observed.Text("Phase") == expected && observed.Flag("Consistent", true)) { warned = true; return observed; }
                    }
                    catch (Exception error) when (error is OperationException or IOException) { }
                    finally { c.Cancellation = token; }
                    throw;
                }
            }
            string Relative(string path) => Path.GetRelativePath(store.Paths.Private, path).Replace('\\', '/');
            void Capture(string relative, string? expected = null)
            {
                var locals = record["LocalFiles"]!.AsObject(); if (locals.ContainsKey(relative)) return;
                var path = SafePath.Resolve(store.Paths.Private, relative); var raw = File.Exists(path) ? File.ReadAllBytes(path) : null;
                if (expected != null && (raw == null ? "Absent" : ArchiveStore.Digest(raw)) != expected) throw new OperationException("建立恢复点前来源再次变化，请重新审阅。");
                locals[relative] = new JsonObject { ["Before"] = raw == null ? null : Convert.ToBase64String(raw), ["BeforeHash"] = raw == null ? "Absent" : ArchiveStore.Digest(raw), ["CurrentHash"] = raw == null ? "Absent" : ArchiveStore.Digest(raw) };
                if (raw != null) CryptographicOperations.ZeroMemory(raw);
            }
            void WriteLocal(string relative, JsonObject value, bool secret = false)
            {
                var path = SafePath.Resolve(store.Paths.Private, relative); var item = record["LocalFiles"]![relative]!.AsObject();
                if (ClientSchemes.SourceFingerprint(path) != item.Text("CurrentHash")) throw new OperationException("本地来源在换址期间发生变化，未覆盖。", true, "AddressLocalDrift");
                item["After"] = value.DeepClone(); item["Secret"] = secret; Save();
                if (secret) store.WriteSecret(path, value); else ArchiveStore.WriteJson(path, value);
                item["CurrentHash"] = ClientSchemes.SourceFingerprint(path); Save();
            }
            void VerifyLocalCurrent()
            {
                foreach (var (relative, value) in record["LocalFiles"]!.AsObject())
                    if (ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Private, relative)) != value!.Text("CurrentHash")) throw new OperationException("参与换址的本地来源在同步后变化，已停止提交并保留外部编辑。", true, "AddressLocalDrift");
            }
            void SaveHost(Context c)
            {
                c.State["AddressChangeTransaction"] = new JsonObject { ["Id"] = id, ["OwnerInstance"] = request.InstanceRelativePath };
                WriteLocal(Relative(c.File("deployment-plan.json")), c.Plan);
                WriteLocal(Relative(c.File("deployment-state.json")), c.State);
            }
            async Task UpdateObserved(Context c, JsonObject response)
            {
                foreach (var resource in Host(c)["Resources"]!.AsArray().OfType<JsonObject>())
                {
                    var kind = resource.Text("Kind"); var hash = response.Text("Hashes." + kind); if (hash.Length != 64) throw new OperationException("换址组件缺少实际归属摘要。");
                    if (kind is "TcpForwarding" or "UdpForwarding")
                    { c.State.Put(kind + ".RemoteHash", JsonValue.Create(hash)); c.State.Put(kind + ".ConfigurationFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(c.Plan[kind]!))); }
                    else if (kind.StartsWith("WireGuardTunnel", StringComparison.Ordinal))
                    { if (Host(c).Text("ProjectedHashes." + kind) != hash) throw new OperationException("隧道实际摘要与预检推导不同，未沿用旧的线路依赖。"); c.State.Put(kind + ".RemoteHash", JsonValue.Create(hash)); c.State.Put(kind + ".ConfigurationFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(c.Plan[kind]!))); }
                    else if (kind == "Inbounds")
                    {
                        var observed = response.At("Observations.Inbounds")!;
                        c.State.Put("Inbounds.RemoteHash", JsonValue.Create(hash)); c.State.Put("Inbounds.ModelFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(c.Plan["InboundModel"]!)));
                        c.State.Put("Inbounds.Runtime", observed["Runtime"]!.DeepClone()); c.State.Put("Inbounds.Bindings", observed.At("Registry.Bindings")!.DeepClone());
                    }
                    else if (InstanceAddressChanges.ProtocolFiles.Any(p => p.Role == kind))
                    {
                        var name = InstanceAddressChanges.ProtocolFiles.Single(p => p.Role == kind).File;
                        var remote = kind == "RealityEntry" ? "/usr/local/etc/xray/config.json" : kind == "AnyTlsEntry" ? "/etc/sing-box-anytls/config.json" : "/etc/sing-box/config.json";
                        await using var session = await c.Session(); var bytes = await session.ReadFileAsync(remote, c.Cancellation);
                        if (ArchiveStore.Digest(bytes) != hash) throw new OperationException("换址期间服务器配置发生变化。");
                        var relative = Relative(c.File("server-configs/" + name)); var item = record["LocalFiles"]![relative]!.AsObject();
                        if (ClientSchemes.SourceFingerprint(c.File("server-configs/" + name)) != item.Text("CurrentHash")) throw new OperationException("服务器配置归档含外部改动，未覆盖。", true);
                        item["AfterBytes"] = Convert.ToBase64String(bytes); Save(); ArchiveStore.AtomicWrite(c.File("server-configs/" + name), bytes); item["CurrentHash"] = hash; Save();
                        c.State.Put("ServerConfigHashes." + kind, JsonValue.Create(hash));
                    }
                }
                SaveHost(c);
            }
            async Task ValidateAll()
            {
                // Providers are checked before consumers so refreshed independent
                // inbound sources have actual current validation, not old evidence.
                foreach (var c in AddressValidationOrder(contexts))
                {
                    await VerifyManagement(c);
                    var result = await validation.ValidateAsync(c.Plan, c.Secrets, c.File("address-validation/" + id), user, new InlineProgress<string>(m => c.Report("换址协议验收", m)), c.Cancellation);
                    if (result.Text("Status") is not ("Passed" or "NoEnabledProtocols")) throw new OperationException("换址后的代理 HTTPS／出口／UDP 验收未完成。");
                    c.State["ProtocolValidation"] = result.DeepClone();
                    foreach (var role in ServerOutboundRouting.Roles.Where(role => Enabled(c.Plan, role))) await ValidateAdditionalHops(c, role);
                    if (c.Plan["InboundModel"] is JsonObject model)
                    {
                        var ids = InboundCatalog.Items(model, "Inbounds").Select(i => i.Text("Id")).ToArray();
                        if (ids.Length > 0)
                        {
                            if (inboundValidation == null) throw new OperationException("独立入站的实际验收适配器不可用。");
                            var credentials = c.Secrets["Inbounds"]!.AsObject();
                            var proof = await inboundValidation.ValidateAsync(c.Plan, model, credentials, ids, c.File("address-validation/" + id + "/inbounds"), new InlineProgress<string>(m => c.Report("换址入站验收", m)), c.Cancellation);
                            await ValidateInboundPolicies(c, model, credentials, ids, proof);
                            InboundSources.RequireValidation(store, c.Plan, model, credentials, ids, proof);
                            var byId = new JsonObject();
                            foreach (var group in proof["Items"]!.AsArray().OfType<JsonObject>().GroupBy(i => i.Text("InboundId"))) byId[group.Key] = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(group.Select(v => (JsonNode?)v.DeepClone()).ToArray()) };
                            c.State.Put("Inbounds.ValidationById", byId); c.State.Put("Inbounds.LastCheck", JsonValue.Create("Passed"));
                        }
                    }
                    foreach (var transport in new[] { "TcpForwarding", "UdpForwarding" })
                    {
                        if (c.Plan[transport] is not JsonObject config) continue;
                        var ordinary = config.DeepClone().AsObject(); foreach (var rule in ordinary["Rules"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("Validation.Type") == "TcpChain").ToArray()) ordinary["Rules"]!.AsArray().Remove(rule);
                        if (ordinary["Rules"]!.AsArray().Count == 0) continue;
                        JsonObject proof;
                        if (transport == "TcpForwarding") { if (tcpForwarding == null) throw new OperationException("TCP 转发实际验收不可用。"); proof = await tcpForwarding.ValidateAsync(c.Plan, ordinary, c.File("address-validation/" + id + "/tcp"), new InlineProgress<string>(m => c.Report("换址 TCP 验收", m)), c.Cancellation); }
                        else { if (udpForwarding == null) throw new OperationException("UDP 转发实际验收不可用。"); proof = await udpForwarding.ValidateAsync(c.Plan, ordinary, c.File("address-validation/" + id + "/udp"), new InlineProgress<string>(m => c.Report("换址 UDP 验收", m)), c.Cancellation); }
                        if (TcpForwarding.Rules(ordinary).Any(r => r.Flag("Enabled") && r["TargetGroup"] is JsonObject))
                        {
                            var asset = transport == "TcpForwarding" ? "tcp-forward-read.sh" : "udp-forward-read.sh";
                            var marker = transport == "TcpForwarding" ? "TCP_FORWARD_READ" : "UDP_FORWARD_READ";
                            var hash = c.State.Text(transport + ".RemoteHash");
                            var groups = await c.Run(asset, new() { ["PROBE_GROUPS"] = "true", ["EXPECTED_HASH"] = hash }, false, 180, marker);
                            ForwardTargetGroups.AttachProof(ordinary, proof, JsonNode.Parse(RemoteAssets.Marker(groups.Output, "FORWARD_GROUP_PROBE"))!.AsObject(), hash, true);
                        }
                        if (transport == "TcpForwarding") TcpForwarding.RequireValidation(ordinary, proof); else UdpForwarding.RequireValidation(c.Plan, ordinary, proof);
                        c.State.Put(transport + ".Validation", proof);
                    }
                    SaveHost(c);
                }
                await ValidateAddressTopologies(contexts, record, WriteLocal, id);
                foreach (var c in contexts)
                {
                    var status = await Remote(c, "Status");
                    foreach (var r in Host(c)["Resources"]!.AsArray().OfType<JsonObject>())
                        if (r.Text("Kind") != "Firewall" && status.Text("Hashes." + r.Text("Kind")) != c.State.Text(r.Text("Kind") is "RealityEntry" or "AnyTlsEntry" or "ShadowsocksLanding" ? "ServerConfigHashes." + r.Text("Kind") : r.Text("Kind") + ".RemoteHash")) throw new OperationException("验收期间受管配置发生变化，未提交。");
                }
            }
            async Task RestoreAll()
            {
                record["Phase"] = "Restoring"; Save();
                foreach (var c in contexts) c.Cancellation = CancellationToken.None;
                // Read every local file before any restore. Never overwrite an
                // external edit, including one that occurred after a crash.
                foreach (var (relative, value) in record["LocalFiles"]!.AsObject())
                {
                    var item = value!.AsObject(); var path = SafePath.Resolve(store.Paths.Private, relative); var actual = ClientSchemes.SourceFingerprint(path);
                    if (actual == item.Text("BeforeHash") || actual == item.Text("CurrentHash")) continue;
                    if (item["AfterBytes"] != null && actual == ArchiveStore.Digest(Convert.FromBase64String(item.Text("AfterBytes")))) continue;
                    if (item["After"] is JsonObject after && File.Exists(path))
                    {
                        var current = item.Flag("Secret") ? store.ReadSecret(path) : ArchiveStore.ReadJson(path);
                        if (JsonNode.DeepEquals(current, after)) continue;
                    }
                    throw new OperationException("本地归档含外部改动，换址恢复已停止。", true, "AddressRecoveryDrift");
                }
                foreach (var c in contexts.AsEnumerable().Reverse().Where(c => record["Attempted"]!.AsArray().Any(v => v!.ToString() == c.Request.InstanceRelativePath)))
                {
                    var phase = await Remote(c, "Status"); if (phase.Text("Phase") == "Absent") continue;
                    var restored = await Remote(c, "Rollback"); if (restored.Text("Phase") != "RolledBack") throw new OperationException("远端换址恢复尚未确认。", true);
                }
                foreach (var (relative, value) in record["LocalFiles"]!.AsObject())
                {
                    var item = value!.AsObject(); var path = SafePath.Resolve(store.Paths.Private, relative);
                    if (item["Before"] == null) { if (File.Exists(path)) File.Delete(path); }
                    else ArchiveStore.AtomicWrite(path, Convert.FromBase64String(item.Text("Before")));
                }
                record["Phase"] = "RolledBack"; Save();
            }
            if (recovering) { Begin("recovery"); await RestoreAll(); Done(); return TaskOutcome.Completed; }
            Begin("identity"); foreach (var c in contexts) await VerifyManagement(c); Done();
            Begin("preflight");
            foreach (var c in contexts)
            {
                var audit = await c.Run("audit.sh"); Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
                if (Host(c)["Resources"]!.AsArray().Any(r => r!.Text("Kind") == "Firewall")) await c.Run("firewall-preflight.sh", FirewallParameters(Host(c)["Before"]!.AsObject(), true), marker: "FIREWALL_SCOPE_OK");
                var observed = await Remote(c, "Inspect"); Host(c)["ProjectedHashes"] = observed["ProjectedHashes"]?.DeepClone() ?? new JsonObject();
            }
            // Rebuild before the first snapshot: an external source edit during
            // SSH verification invalidates the reviewed candidate.
            if (InstanceAddressChanges.Prepare(store, request).Fingerprint != preview.Fingerprint) throw new OperationException("身份核对期间来源发生变化，请重新审阅。");
            var participantScope = contexts.Select(c => c.Request.InstanceRelativePath).ToHashSet(StringComparer.Ordinal);
            InstanceAddressChanges.CompleteReferences(store, document, store.ListInstances().ToArray());
            if (!participantScope.SetEquals(document["Hosts"]!.AsArray().Select(h => h!.Text("Instance")))) throw new OperationException("依赖闭包在预检后变化，请重新审阅。");
            foreach (var c in contexts)
            {
                c.Plan.Clear(); foreach (var field in Host(c)["After"]!.AsObject()) c.Plan[field.Key] = field.Value?.DeepClone();
                await Remote(c, "Inspect");
            }
            record["Document"] = document.DeepClone();
            Done(); Begin("backup");
            foreach (var c in contexts)
            {
                Capture(Relative(c.File("deployment-plan.json")), Host(c).Text("Hashes.Plan")); Capture(Relative(c.File("deployment-state.json")), Host(c).Text("Hashes.State"));
                if (ClientSchemes.SourceFingerprint(c.File("secrets.dotnet.private.json")) != Host(c).Text("Hashes.Secrets")) throw new OperationException("凭据在建立恢复点前发生变化，未开始换址。");
            }
            foreach (var item in document["Files"]!.AsArray().OfType<JsonObject>()) Capture(item.Text("Path"), item.Text("Hash"));
            Capture("ssh-hosts.dotnet.json"); Save();
            foreach (var c in contexts)
            {
                c.State["AddressChangeTransaction"] = new JsonObject { ["Id"] = id, ["OwnerInstance"] = request.InstanceRelativePath };
                WriteLocal(Relative(c.File("deployment-state.json")), c.State);
            }
            foreach (var c in contexts)
            {
                record["Attempted"]!.AsArray().Add(c.Request.InstanceRelativePath); Save();
                await Remote(c, "Prepare");
            }
            Done(); Begin("bridge"); foreach (var c in contexts) await Remote(c, "Bridge"); Done();
            Begin("apply");
            foreach (var c in contexts) await Remote(c, "Apply");
            foreach (var file in document["Files"]!.AsArray().OfType<JsonObject>()) WriteLocal(file.Text("Path"), file["After"]!.AsObject(), file.Flag("Secret"));
            foreach (var c in contexts) await UpdateObserved(c, await Remote(c, "Status"));
            record["Phase"] = "Applied"; Save(); Done();
            Begin("validation"); await ValidateAll(); Done();
            Begin("finalize"); VerifyLocalCurrent(); foreach (var c in contexts) await UpdateObserved(c, await Remote(c, "Finalize")); await ValidateAll();
            foreach (var c in contexts.Where(c => Host(c)["Resources"]!.AsArray().Any(r => r!.Text("Kind") == "Firewall"))) await c.Run("firewall-preflight.sh", FirewallParameters(c.Plan, true), marker: "FIREWALL_SCOPE_OK"); Done();
            Begin("commit"); VerifyLocalCurrent(); record["Phase"] = "Validated"; Save();
            foreach (var c in contexts) await Remote(c, "Commit");
            VerifyLocalCurrent();
            var trustPath = store.Paths.Resolve("private/ssh-hosts.dotnet.json"); var trust = File.Exists(trustPath) ? ArchiveStore.ReadJson(trustPath) : new JsonObject();
            foreach (var c in contexts) { var key = ArchiveStore.Digest(Encoding.UTF8.GetBytes(c.Plan.Text("Server.IPv4"))); if (trust[key] != null && trust.Text(key) != c.HostPin) throw new OperationException("新管理地址存在不同的 SSH 身份，未覆盖。", true); trust[key] = c.HostPin; }
            WriteLocal("ssh-hosts.dotnet.json", trust);
            foreach (var c in contexts) { c.State.Remove("AddressChangeTransaction"); c.State["LastAddressChange"] = new JsonObject { ["Id"] = id, ["Status"] = "Passed", ["At"] = DateTimeOffset.UtcNow }; WriteLocal(Relative(c.File("deployment-state.json")), c.State); }
            record["Phase"] = "Committed"; Save(); Done();
            return warned ? TaskOutcome.CompletedWithWarnings : TaskOutcome.Completed;
        }
        catch (Exception error)
        {
            if (!journalExists) throw;
            record["Phase"] = "NeedsRecovery"; record["Failure"] = error is OperationCanceledException ? "Cancelled" : SafeFailures.Describe(error).Code ?? "AddressChangeFailed"; Save();
            // Recovery uses the original multi-host journal, including a prepared
            // snapshot whose acknowledgement was lost. No mutation is retried.
            try
            {
                foreach (var c in contexts) { c.Cancellation = CancellationToken.None; c.State["AddressChangeTransaction"] = new JsonObject { ["Id"] = id, ["OwnerInstance"] = request.InstanceRelativePath }; }
                if (!recovering)
                {
                    var recovery = new OperationRequest(OperationKind.InstanceAddress, request.InstanceRelativePath, new JsonObject { ["Action"] = "Recover", ["Id"] = id });
                    await ChangeInstanceAddress(recovery, taskId, progress, CancellationToken.None);
                }
                else throw new OperationException("换址恢复尚未完成，保留所有参与实例和恢复点。", true, "AddressNeedsRecovery");
            }
            catch { throw new OperationException("换址或恢复未全部确认，请从原实例“恢复换址”继续核对，不能重新执行原变更。", true, "AddressNeedsRecovery"); }
            if (error is OperationCanceledException) throw;
            throw new OperationException("换址未完成，本次受管资源及归档已恢复。", code: "AddressChangeRolledBack");
        }
        finally { InstanceAddressChanges.Owner.Value = previousOwner; foreach (var context in contexts) await context.DisposeAsync(); }
    }
    private IReadOnlyList<Context> AddressValidationOrder(List<Context> contexts)
    {
        var result = new List<Context>(); var visiting = new HashSet<string>();
        void Visit(Context c)
        {
            if (result.Contains(c)) return; var relative = c.Request.InstanceRelativePath;
            if (!visiting.Add(relative)) throw new OperationException("受影响来源形成循环，不能确定换址验收顺序。");
            var references = new List<(string Scheme, string Node)>();
            foreach (var outbound in InboundCatalog.Items(c.Plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Outbounds").Where(o => o.Text("Kind") == "Proxy")) references.Add((outbound.Text("Source.SchemeId"), outbound.Text("Source.NodeId")));
            foreach (var role in ServerOutboundRouting.Roles) if (c.Plan.At("ServerOutbound." + role) is JsonObject route) foreach (var r in new[] { route }.Concat((route["AdditionalHops"] as JsonArray ?? []).OfType<JsonObject>())) if (r.Text("SchemeId") != "") references.Add((r.Text("SchemeId"), r.Text("NodeId")));
            foreach (var reference in references)
            {
                var scheme = store.ReadSecret(ServerOutboundRouting.SchemeFile(store.Paths, reference.Scheme));
                try { var node = scheme["Nodes"]!.AsArray().Single(n => n!.Text("Id") == reference.Node)!; var instance = node.Text("InboundOrigin.Instance", node.Text("ManagedOrigin.Instance", node.Text("ForwardedOrigin.Instance"))); var provider = contexts.SingleOrDefault(p => p.Request.InstanceRelativePath == instance); if (provider != null) Visit(provider); }
                finally { scheme.Clear(); }
            }
            visiting.Remove(relative); result.Add(c);
        }
        foreach (var c in contexts) Visit(c); return result;
    }
    private async Task ValidateAddressTopologies(List<Context> contexts, JsonObject record, Action<string, JsonObject, bool> write, string id)
    {
        foreach (var tunnel in WireGuardTunnels.List(store).Where(r => r.Text("Phase") == "Active" && WireGuardTunnels.Instances(r["Configuration"]!.AsObject()).Any(i => contexts.Any(c => c.Request.InstanceRelativePath == i))))
        {
            var config = tunnel["Configuration"]!.AsObject(); var first = contexts.SingleOrDefault(c => c.Request.InstanceRelativePath == config.Text("FirstInstance")); var second = contexts.SingleOrDefault(c => c.Request.InstanceRelativePath == config.Text("SecondInstance"));
            if (first == null || second == null) throw new OperationException("换址隧道缺少另一端依赖，请重新读取两端归档。");
            tunnel["Validation"] = await WireGuardProof(first, second, config); var path = "wireguard-tunnels/" + config.Text("Id") + ".json";
            if (record["LocalFiles"]![path] != null) write(path, tunnel, false);
        }
        foreach (var chain in TcpChains.List(store).Where(r => r.Text("Phase") == "Active" && TcpChains.Instances(r["Configuration"]!.AsObject()).Any(i => contexts.Any(c => c.Request.InstanceRelativePath == i))))
        {
            if (tcpChains == null) throw new OperationException("跨实例线路实际验收不可用。"); var config = chain["Configuration"]!.AsObject(); var node = TcpChains.Project(store, config, "Address validation");
            var proof = await tcpChains.ValidateAsync(node, store.Paths.Resolve("private/address-validation/" + id + "/" + config.Text("Id")), new InlineProgress<string>(_ => { }), contexts[0].Cancellation);
            proof["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(config);
            if (TcpChainUnderlay.Selected(config))
            {
                var pieces = new JsonArray();
                foreach (var reference in TcpChainUnderlay.References(config))
                {
                    var t = ArchiveStore.ReadJson(WireGuardTunnels.FileName(store.Paths, reference.Text("Id"))); var c = t["Configuration"]!.AsObject();
                    var p = await WireGuardProof(contexts.Single(x => x.Request.InstanceRelativePath == c.Text("FirstInstance")), contexts.Single(x => x.Request.InstanceRelativePath == c.Text("SecondInstance")), c);
                    p["Id"] = reference.Text("Id"); p["Segment"] = reference.Text("Segment"); p["DependencyFingerprint"] = reference.Text("Fingerprint"); pieces.Add(p);
                }
                proof["WireGuard"] = config.ContainsKey("WireGuards") ? new JsonObject { ["Status"] = "Passed", ["Scope"] = "AdjacentWireGuardApplications", ["Segments"] = pieces } : pieces[0]!.DeepClone();
            }
            TcpChains.RequireValidation(config, node, proof); chain["Validation"] = proof; chain["LastCheck"] = new JsonObject { ["Status"] = "Passed", ["At"] = DateTimeOffset.UtcNow }; TcpChains.SealRules(store, chain);
            var path = "tcp-chains/" + config.Text("Id") + ".json"; if (record["LocalFiles"]![path] != null) write(path, chain, false);
        }
    }
}
