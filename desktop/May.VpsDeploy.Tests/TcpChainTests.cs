using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunTcpChainTests()
    {
        await TcpChainExperience();
        Console.WriteLine($"PASS: {assertions} cross-instance TCP review, dependency, commit-loss, compensation, cancellation and source assertions; no production connections.");
    }
    private async Task TcpChainExperience()
    {
        foreach (var failure in new[] { "none", "machine-alias", "relay-drift", "landing-drift", "arm-before", "arm-ack", "apply-ack", "validation", "incomplete", "cancel", "commit-ack", "commit-front", "compensation-ack", "rollback", "owner" })
        {
            using var f = new Fixture(repository); var remote = new ChainRemote(); var plans = new List<JsonObject>();
            for (var i = 0; i < 3; i++)
            {
                var plan = f.Plan("Chain-" + failure + "-" + i); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Server.IPv4", JsonValue.Create("192.0.2." + (10 + i))); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan); plans.Add(plan);
                var host = new ChainHost(plan.Text("Server.IPv4"), remote); host.Inner.SeedProtocols(plan); host.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("synthetic existing proxy"); remote.Hosts.Add(plan.Text("Server.IPv4"), host);
                if (i < 2)
                {
                    var config = ForwardConfig(55000 + i); host.Configuration = config.DeepClone().AsObject(); plan["TcpForwarding"] = config.DeepClone(); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json"), plan);
                    var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile);
                    state["TcpForwarding"] = new JsonObject { ["RemoteHash"] = ArchiveStore.Fingerprint(config), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(config), ["Validation"] = await new ForwardValidation("none").ValidateAsync(plan, config, "unused", new InlineProgress<string>(_ => { }), default) }; ArchiveStore.WriteJson(stateFile, state);
                }
            }
            var front = remote.Hosts[plans[0].Text("Server.IPv4")]; var relay = remote.Hosts[plans[1].Text("Server.IPv4")]; var landing = remote.Hosts[plans[2].Text("Server.IPv4")];
            var statePath = SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "deployment-state.json"); var landingState = ArchiveStore.ReadJson(statePath); landingState.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ArchiveStore.Digest(landing.Inner.ProtocolConfigs["RealityEntry"]))); ArchiveStore.WriteJson(statePath, landingState);
            var scheme = ClientSchemes.New(f.Paths); var credentials = f.Store.ReadSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "secrets.dotnet.private.json"));
            var pair = ClientProfiles.Nodes(plans[2], credentials).First(); credentials.Clear();
            var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = pair.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(plans[2]), pair) };
            scheme["Nodes"]!.AsArray().Add(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            var configChain = TcpChains.New(f.Relative(plans[0])); configChain["RelayInstance"] = f.Relative(plans[1]); configChain["LandingInstance"] = f.Relative(plans[2]); configChain["FrontSourceAddress"] = plans[0].Text("Server.IPv4"); configChain["FrontSources"] = new JsonArray("198.51.100.0/24"); configChain["Landing"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            OperationRequest Request(string action) => new(OperationKind.TcpChain, f.Relative(plans[0]), new JsonObject { ["Action"] = action, ["Configuration"] = configChain.DeepClone() });
            var validator = new ChainValidation { Failure = failure, Remote = remote };
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: new ForwardValidation("none"), tcpChains: validator);
            var coordinator = new TaskCoordinator(f.Store, engine); var reports = new List<TaskProgress>(); var progress = new InlineProgress<TaskProgress>(reports.Add);
            var preview = TcpChains.Prepare(f.Store, Request("Apply"));
            Check(preview.FrontConfiguration["Rules"]!.AsArray().Count == 2 && preview.RelayConfiguration["Rules"]![1]!.Text("TargetAddress") == plans[2].Text("Server.IPv4") && preview.RelayConfiguration["Rules"]![1]!.Strings("AllowedSources").Single() == plans[0].Text("Server.IPv4") + "/32", "topology, preserved rules or relay source scope incorrect");
            Check(!preview.Summary.Contains(node.Text("sing_box.uuid")) && preview.Summary.Contains("前置") && preview.Summary.Contains("中转"), "review leaked auth or omitted the route");
            if (failure == "none")
            {
                var bad = Request("Apply"); bad.Options["Configuration"]!["RelayInstance"] = f.Relative(plans[0]); Refuses(() => coordinator.Review(bad), "self-loop participants accepted");
                bad = Request("Apply"); bad.Options["Configuration"]!["FrontPort"] = plans[0].Number("Ports.SshPrimary"); Refuses(() => coordinator.Review(bad), "management port collision accepted");
                var monitorReserved = plans[0].DeepClone().AsObject(); monitorReserved.Put("MayMonitorServer.Port", JsonValue.Create(configChain.Number("FrontPort"))); var frontPlanFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plans[0])), "deployment-plan.json"); ArchiveStore.WriteJson(frontPlanFile, monitorReserved);
                Refuses(() => coordinator.Review(Request("Apply")), "an installed monitoring port could be reused while stopped"); ArchiveStore.WriteJson(frontPlanFile, plans[0]);
                var reviewLocked = coordinator.Review(Request("Apply"));
                using (f.Store.LockInstance(f.Relative(plans[1]))) await RefusesAsync(() => coordinator.ExecuteAsync(reviewLocked, Request("Apply"), progress, default), "relay participant lock ignored");
                using (f.Store.LockInstance(f.Relative(plans[0]))) Check(remote.Events.Count == 0, "partial lock failure leaked a lock or made a connection");
                var stale = coordinator.Review(Request("Apply")); var changed = landingState.DeepClone().AsObject(); changed["Synthetic"] = 1; ArchiveStore.WriteJson(statePath, changed);
                await RefusesAsync(() => coordinator.ExecuteAsync(stale, Request("Apply"), progress, default), "landing archive change bypassed multi-instance review fingerprint"); ArchiveStore.WriteJson(statePath, landingState);
                var changedHelper = f.Paths.Resolve("assets/remote/tcp-chain-rollback.sh"); var originalHelper = File.ReadAllBytes(changedHelper); var reviewedHelper = coordinator.Review(Request("Apply")); File.AppendAllText(changedHelper, "\n# synthetic changed helper\n");
                await RefusesAsync(() => coordinator.ExecuteAsync(reviewedHelper, Request("Apply"), progress, default), "changed recovery helper bypassed the reviewed asset identity"); File.WriteAllBytes(changedHelper, originalHelper);
            }
            relay.Drift = failure == "relay-drift"; if (failure == "landing-drift") landing.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("changed remotely");
            relay.Failure = failure;
            if (failure == "machine-alias") relay.MachineAddress = front.Address;
            if (failure == "commit-front") front.Failure = failure;
            var record = await coordinator.ExecuteAsync(coordinator.Review(Request("Apply")), Request("Apply"), progress, default);
            var chainFile = TcpChains.FileName(f.Paths, configChain.Text("Id")); var saved = ArchiveStore.ReadJson(chainFile);
            Check(landing.ApplyCalls == 0 && landing.Inner.Mutations == 0 && landing.Inner.ProtocolConfigs["RealityEntry"].AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(failure == "landing-drift" ? "changed remotely" : "synthetic existing proxy")), "orchestration wrote landing proxy or unrelated services");
            if (failure == "none")
            {
                Check(record.Outcome == TaskOutcome.Completed && saved.Text("Phase") == "Active", "successful chain not active: " + record.SafeError);
                Check(reports.Any(p => p.Steps?.Count == 5) && reports.Count(p => p.StepState == TaskStepState.Completed && p.StepId?.StartsWith("chain-", StringComparison.Ordinal) == true) == 5, "cross-instance UI progress omitted its staged plan or completion");
                Check(remote.Events.IndexOf(relay.Address + ":apply") < remote.Events.IndexOf(front.Address + ":apply") && remote.Events.IndexOf("validation") >= 0 && remote.Events.IndexOf("validation") < remote.Events.IndexOf(relay.Address + ":commit"), "apply ordering or whole-path validation barrier incorrect");
                var projected = TcpChains.Project(f.Store, configChain, "US-West-LA Entry"); TcpChains.VerifyNodes(f.Store, [projected]);
                Check(projected.Text("sing_box.server") == front.Address && projected.Number("clash.port") == configChain.Number("FrontPort") && projected.Text("sing_box.uuid") == node.Text("sing_box.uuid") && projected.Text("sing_box.tls.server_name") == node.Text("sing_box.tls.server_name"), "client endpoint projection lost auth or SNI");
                var choices = ForwardedNodeSources.Choices(f.Store, "US-West-LA Entry"); Check(choices.Any(c => c.RuleId == configChain.Text("Id") && c.Node != null), "chain unavailable in client source chooser");
                var targetScheme = ClientSchemes.New(f.Paths); ForwardedNodeSources.Apply(f.Store, targetScheme, [projected], "US-West-LA Entry"); Check(targetScheme["Nodes"]!.AsArray().Count == 1, "chain node could not be added to scheme");
                f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, targetScheme.Text("Id")), targetScheme); var nested = TcpForwarding.NewRule(); nested["TargetAddress"] = projected.Text("sing_box.server"); nested["TargetPort"] = projected.Number("sing_box.server_port"); nested["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = targetScheme.Text("Id"), ["NodeId"] = projected.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(projected) };
                Refuses(() => TcpForwarding.ProxyNode(f.Store, nested), "a chain projection could be reused as an unverified nested forwarding source");
                Refuses(() => new InstanceDeletion(f.Store).Review(f.Relative(plans[2])), "landing archive could be deleted while referenced");
                Refuses(() => coordinator.Review(new(OperationKind.TcpForward, f.Relative(plans[1]), TcpForwarding.Options(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[1])), "deployment-state.json")), "Remove"))), "single-host editor could remove a chain-owned relay");
                var before = front.ApplyCalls + relay.ApplyCalls;
                var checkedRecord = await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default);
                Check(checkedRecord.Outcome == TaskOutcome.Completed && before == front.ApplyCalls + relay.ApplyCalls, "read-only chain check mutated forwarding");
                validator.Failure = "validation";
                Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default)).Outcome == TaskOutcome.Failed && before == front.ApplyCalls + relay.ApplyCalls, "failed read-only check mutated the chain or reported success");
                Refuses(() => TcpChains.VerifyNodes(f.Store, [projected]), "known failed check left the node exportable"); validator.Failure = "";
                Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default)).Outcome == TaskOutcome.Completed, "successful recheck did not clear a previous failure");
                front.Failure = "apply-ack";
                Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Remove")), Request("Remove"), progress, default)).Outcome == TaskOutcome.Failed && ArchiveStore.ReadJson(chainFile).Text("Phase") == "Active", "failed removal lost the prior active route"); front.Failure = "";
                TcpChains.VerifyNodes(f.Store, [projected]); Check(true, "failed removal did not restore prior client provenance");
                var altered = projected.DeepClone().AsObject(); altered["sing_box"]!["uuid"] = "changed"; Refuses(() => TcpChains.VerifyNodes(f.Store, [altered]), "edited auth bypassed chain source verification");
                landing.Unavailable = true; remote.Events.Clear();
                var removed = await coordinator.ExecuteAsync(coordinator.Review(Request("Remove")), Request("Remove"), progress, default);
                Check(removed.Outcome == TaskOutcome.Completed && ArchiveStore.ReadJson(chainFile).Text("Phase") == "Removed", "chain removal requires an online landing or failed: " + removed.SafeError);
                Check(remote.Events.IndexOf(front.Address + ":apply") < remote.Events.IndexOf(relay.Address + ":apply"), "removal did not close the front first");
                Refuses(() => TcpChains.VerifyNodes(f.Store, [projected]), "removed chain remained exportable");
                foreach (var p in plans) Check(TcpChains.Plan(f.Store, f.Relative(p))["TcpChain"] == null, "removal left a dependency binding");
            }
            else
            {
                var recoveryNeeded = failure is "rollback" or "owner" or "compensation-ack";
                Check(record.Outcome == (recoveryNeeded ? TaskOutcome.NeedsRecovery : failure == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "unexpected failure outcome " + failure + ": " + record.Outcome + " " + record.SafeError);
                Check(front.ApplyCalls <= 1 && relay.ApplyCalls <= 1, "an unacknowledged mutation was replayed");
                if (recoveryNeeded)
                {
                    Check(saved.Text("Phase") == "NeedsRecovery", "partial recovery reported completion");
                    Refuses(() => coordinator.Review(new(OperationKind.HealthAudit, f.Relative(plans[2]), new())), "pending dependency was not reserved");
                    relay.Failure = ""; relay.Inner.StatusTaskId = saved.Text("Transaction.TaskId");
                    var recovered = await coordinator.ExecuteAsync(coordinator.Review(Request("Recover")), Request("Recover"), progress, default);
                    Check(recovered.Outcome == TaskOutcome.Completed && ArchiveStore.ReadJson(chainFile).Text("Phase") == "RolledBack", "coordinated recovery did not finish: " + recovered.SafeError);
                }
                else Check(saved.Text("Phase") == "RolledBack", "failure left an active or partial chain");
                foreach (var host in new[] { front, relay }) Check(host.Configuration != null && host.Configuration["Rules"]!.AsArray().Count == 1 && host.Configuration["Rules"]![0]!.Text("Validation.Type") == "Tls", "failure removed an existing rule or left a chain listener");
                if (failure == "commit-ack") Check(relay.Compensations == 1, "committed participant was not compensated after lost acknowledgement");
                foreach (var p in plans) Check(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(p)), "deployment-state.json"))["TcpChainTransaction"] == null, "finished recovery left a local reservation");
            }
        }
    }
    private sealed class ChainValidation : ITcpChainValidation
    {
        public string Failure { get; set; } = "";
        public ChainRemote? Remote { get; set; }
        public Task<JsonObject> ValidateAsync(JsonObject node, string directory, IProgress<string> progress, CancellationToken cancellationToken)
        {
            Remote?.Events.Add("validation");
            if (Failure is "validation" or "rollback" or "owner") throw new OperationException("synthetic whole-path failure");
            if (Failure == "cancel") throw new OperationCanceledException();
            return Task.FromResult(new JsonObject { ["Status"] = Failure == "incomplete" ? "Incomplete" : "Passed", ["From"] = "Controller", ["Scope"] = "TcpChainProxyHttps", ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Result"] = new JsonObject { ["Status"] = "Reachable" } });
        }
    }
    private sealed class ChainRemote : IRemoteSessionFactory
    {
        public Dictionary<string, ChainHost> Hosts { get; } = new(); public List<string> Events { get; } = [];
        public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken cancellationToken) => Hosts[endpoint.Host].Unavailable ? throw new IOException("synthetic unavailable host") : Task.FromResult<IRemoteSession>(Hosts[endpoint.Host]);
    }
    private sealed class ChainHost(string address, ChainRemote owner) : IRemoteSession
    {
        public string Address => address; public FakeRemote Inner { get; } = new(); public JsonObject? Configuration { get; set; } private JsonObject? original;
        public bool Unavailable { get; set; } public bool Drift { get; set; } public string Failure { get; set; } = ""; public string? MachineAddress { get; set; } public int ApplyCalls { get; private set; } public int Compensations { get; private set; }
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => Inner.RunAsync(command, timeout, ct);
        public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken ct)
        {
            var asset = payload.Split('\n')[0].Replace("# MXH asset: ", "");
            string Parameter(string name) { var match = Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' "); return match.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) : ""; }
            static string Marker(string name, string value) => "VPSDEPLOY_" + name + "_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value)) + "\n";
            if (asset == "tcp-forward-read.sh") return new(0, Marker("TCP_FORWARD_STATE", new JsonObject { ["Hash"] = Drift ? new string('f', 64) : Configuration == null ? "Absent" : ArchiveStore.Fingerprint(Configuration), ["Configuration"] = Configuration?.DeepClone(), ["TemplateCurrent"] = true }.ToJsonString()) + "VPSDEPLOY_TCP_FORWARD_READ\n", "");
            if (asset == "protocol-migration-arm-rollback.sh") { original = Configuration?.DeepClone().AsObject(); Inner.StatusTaskId = Parameter("CONTROL_TASK_ID"); Inner.StatusPhase = Failure == "arm-before" ? "Preparing" : "Armed"; if (Failure is "arm-ack" or "arm-before") throw new IOException("synthetic lost snapshot acknowledgement"); }
            if (asset == "tcp-forward-apply.sh")
            {
                owner.Events.Add(address + ":apply"); ApplyCalls++; Configuration = Parameter("ACTION") == "Remove" ? null : JsonNode.Parse(Parameter("CONFIG_JSON"))!.AsObject();
                if (Failure == "apply-ack") throw new IOException("synthetic lost apply acknowledgement");
                return new(0, "VPSDEPLOY_TCP_FORWARD_APPLIED\n", "");
            }
            if (asset == "tcp-chain-probe.sh") return new(0, Marker("TCP_CHAIN_PROBE", new JsonObject { ["Address"] = Parameter("ADDRESS"), ["Port"] = int.Parse(Parameter("PORT")), ["SourceAddress"] = address, ["Status"] = "Connected", ["Scope"] = "TcpConnectOnly" }.ToJsonString()) + "VPSDEPLOY_TCP_CHAIN_PROBED\n", "");
            if (asset == "maintenance-transaction-commit.sh")
            {
                owner.Events.Add(address + ":commit"); if (Failure == "commit-front") throw new IOException("synthetic front commit failed");
                Inner.StatusPhase = "Committed";
                if (Failure is "commit-ack" or "compensation-ack") throw new IOException("synthetic lost commit acknowledgement");
            }
            if (asset == "maintenance-transaction-status.sh" && Failure == "owner") Inner.StatusTaskId = new string('e', 32);
            if (asset is "protocol-migration-trigger-rollback.sh" or "tcp-chain-rollback.sh")
            {
                if (Failure == "rollback") throw new IOException("synthetic recovery disconnected");
                Configuration = original?.DeepClone().AsObject();
                if (asset == "tcp-chain-rollback.sh") { Compensations++; Inner.StatusPhase = "ChainRolledBack"; if (Failure == "compensation-ack") throw new IOException("synthetic lost compensation acknowledgement"); return new(0, "VPSDEPLOY_TCP_CHAIN_ROLLED_BACK\n", ""); }
            }
            return await Inner.RunScriptAsync(payload, timeout, mutating, ct);
        }
        public Task<byte[]> ReadFileAsync(string path, CancellationToken ct) => path == "/etc/machine-id" ? Task.FromResult(Encoding.ASCII.GetBytes(ArchiveStore.Digest(Encoding.ASCII.GetBytes(MachineAddress ?? address))[..32])) : Inner.ReadFileAsync(path, ct);
        public Task DownloadAsync(string path, string destination, CancellationToken ct) => Inner.DownloadAsync(path, destination, ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
