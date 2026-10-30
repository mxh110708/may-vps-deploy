using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunWireGuardTests()
    {
        await WireGuardCoverage();
        Console.WriteLine($"PASS: {assertions} WireGuard peer model, two-host coordination, fresh evidence, no replay and scoped recovery assertions; synthetic only.");
    }
    private async Task WireGuardCoverage()
    {
        foreach (var family in new[] { "IPv4", "IPv6" })
            foreach (var failure in new[] { "", "drift", "alias", "arm-before", "arm-ack", "key-ack", "apply-ack", "missing-udp", "stale", "cancel", "commit-ack", "commit-second", "compensation-ack", "rollback", "owner" }) await WireGuardCase(family, failure);
    }
    private async Task WireGuardCase(string family, string failure)
    {
        using var f = new Fixture(repository); var plans = new List<JsonObject>(); var remote = new WireGuardRemote();
        for (var i = 0; i < 2; i++)
        {
            var p = f.Plan("WireGuard-" + i); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting"));
            p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (40 + i))); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (40 + i))); f.SaveInstance(p); plans.Add(p);
            var host = new WireGuardHostFake(p.Text("Server.IPv4"), i); host.Inner.SeedProtocols(p); remote.Hosts.Add(p.Text("Server.IPv4"), host);
        }
        var first = remote.Hosts[plans[0].Text("Server.IPv4")]; var second = remote.Hosts[plans[1].Text("Server.IPv4")];
        var c = WireGuardTunnels.New(f.Relative(plans[0])); c["SecondInstance"] = f.Relative(plans[1]); c["Family"] = family;
        OperationRequest Request(string action) => new(OperationKind.WireGuardTunnel, f.Relative(plans[0]), new() { ["Action"] = action, ["Configuration"] = c.DeepClone() });
        var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation()));
        var progress = new InlineProgress<TaskProgress>(_ => { }); var review = coordinator.Review(Request("Apply"));
        Check(review.Summary.Contains("WireGuard") && review.Summary.Contains(family) && review.Summary.Contains("默认路由"), "tunnel review omitted its scope");
        if (failure == "")
        {
            foreach (var (field, value) in new (string, JsonNode?)[] { ("Version", JsonValue.Create("1")), ("Name", JsonValue.Create(true)), ("FirstPort", JsonValue.Create(1)), ("Mtu", JsonValue.Create(1600)), ("KeepaliveSeconds", JsonValue.Create(1)), ("FirstAddress", JsonValue.Create("8.8.8.8")), ("SecondAddress", JsonValue.Create("10.203.0.1")), ("Family", JsonValue.Create("IPv9")), ("Family", null), ("PrivateKey", JsonValue.Create("unreviewed key")) })
            { var bad = Request("Apply"); bad.Options["Configuration"]![field] = value; Refuses(() => coordinator.Review(bad), "invalid WireGuard model accepted: " + field); }
            var badPeer = Request("Apply"); badPeer.Options["Configuration"]!["SecondInstance"] = f.Relative(plans[0]); Refuses(() => coordinator.Review(badPeer), "same archive used as both peers");
            using (var held = f.Store.LockInstance(f.Relative(plans[1]))) { await RefusesAsync(async () => { await coordinator.ExecuteAsync(review, Request("Apply"), progress, default); }, "second peer lock failed to protect both hosts"); Check(first.ApplyCalls == 0 && second.ApplyCalls == 0, "a locked peer caused a partial mutation"); }
            var p = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[1])), "deployment-plan.json")); p["NodeName"] = "changed after review"; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[1])), "deployment-plan.json"), p);
            await RefusesAsync(async () => { await coordinator.ExecuteAsync(review, Request("Apply"), progress, default); }, "second archive changed without invalidating review"); Check(first.ApplyCalls == 0, "stale review mutated first host");
        }
        first.Failure = failure; if (failure == "commit-second") { first.Failure = ""; second.Failure = failure; }
        second.SameIdentity = failure == "alias";
        var result = await coordinator.ExecuteAsync(coordinator.Review(Request("Apply")), Request("Apply"), progress, default);
        var path = WireGuardTunnels.FileName(f.Paths, c.Text("Id")); var record = ArchiveStore.ReadJson(path);
        Check(first.ApplyCalls <= 1 && second.ApplyCalls <= 1, "lost acknowledgement replayed a tunnel mutation");
        if (failure == "")
        {
            Check(result.Outcome == TaskOutcome.Completed && record.Text("Phase") == "Active", "WireGuard creation failed: " + result.SafeError);
            Check(!Directory.EnumerateFiles(f.Paths.Instance(f.Relative(plans[0])), "remote-files.tar.gz", SearchOption.AllDirectories).Any(), "a WireGuard private-key archive left its host");
            Check(first.Config!.Text("PeerAddress") == c.Text("SecondAddress") && first.Config.Text("PeerPublicKey") == second.Config!.Text("PublicKey"), "peer addresses or public keys cross-wired");
            Check(record["Validation"]!["Directions"]!.AsArray().Count == 2 && first.ProofStarts == first.ProofStops && second.ProofStarts == second.ProofStops, "bidirectional proof or transient cleanup missing");
            Refuses(() => coordinator.Review(new(OperationKind.Decommission, f.Relative(plans[0]), new() { ["Scope"] = "ManagedInstance" })), "tunnel dependency did not block decommission");
            Refuses(() => new InstanceDeletion(f.Store).Review(f.Relative(plans[1])), "archive deletion could orphan a live tunnel");
            var dependentPlan = TcpChains.Plan(f.Store, f.Relative(plans[0]));
            var dependency = TcpForwarding.NewRule(); dependency["TargetAddress"] = c.Text("SecondAddress"); dependentPlan["TcpForwarding"] = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(dependency) };
            ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[0])), "deployment-plan.json"), dependentPlan);
            Refuses(() => coordinator.Review(Request("Remove")), "tunnel removal ignored a dependent forward target");
            dependentPlan.Remove("TcpForwarding"); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[0])), "deployment-plan.json"), dependentPlan);
            var duplicate = c.DeepClone().AsObject(); duplicate["Id"] = Guid.NewGuid().ToString("N"); Refuses(() => WireGuardTunnels.Prepare(f.Store, new(OperationKind.WireGuardTunnel, f.Relative(plans[0]), new() { ["Action"] = "Apply", ["Configuration"] = duplicate })), "host shared by two WireGuard tunnels");
            Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default)).Outcome == TaskOutcome.Completed && first.ApplyCalls == 1, "path check reapplied the tunnel");
            first.Failure = "commit-ack";
            var interruptedRemove = await coordinator.ExecuteAsync(coordinator.Review(Request("Remove")), Request("Remove"), progress, default);
            Check(interruptedRemove.Outcome == TaskOutcome.Failed && first.Config != null && second.Config != null && ArchiveStore.ReadJson(path).Text("Phase") == "Active", "failed removal did not restore the active tunnel");
            first.Failure = "";
            Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default)).Outcome == TaskOutcome.Completed, "restored tunnel did not pass both directions");
            var removed = await coordinator.ExecuteAsync(coordinator.Review(Request("Remove")), Request("Remove"), progress, default);
            Check(removed.Outcome == TaskOutcome.Completed && first.Config == null && second.Config == null && ArchiveStore.ReadJson(path).Text("Phase") == "Removed", "tunnel removal failed: " + removed.SafeError);
        }
        else
        {
            var pending = failure is "owner" or "rollback" or "compensation-ack";
            Check(result.Outcome == (pending ? TaskOutcome.NeedsRecovery : failure == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "unexpected WireGuard failure outcome for " + failure + ": " + result.SafeError);
            if (pending)
            {
                first.Failure = ""; first.Inner.StatusTaskId = record.Text("Transaction.TaskId");
                Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Recover")), Request("Recover"), progress, default)).Outcome == TaskOutcome.Completed, "tunnel recovery could not resume");
            }
            Check(ArchiveStore.ReadJson(path).Text("Phase") == "RolledBack" && first.Config == null && second.Config == null, "failure left active tunnel resources");
        }
        foreach (var p in plans)
        {
            var plan = TcpChains.Plan(f.Store, f.Relative(p)); var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(p)), "deployment-state.json"));
            Check(plan["WireGuardTunnel"] == null && state["WireGuardTunnelTransaction"] == null && plan["TcpForwarding"] == null && plan["UdpForwarding"] == null, "tunnel cleanup leaked reservations or changed forwarding components");
        }
        if (failure == "")
        {
            var statePath = SafePath.Resolve(f.Paths.Instance(f.Relative(plans[0])), "deployment-state.json"); var orphan = ArchiveStore.ReadJson(statePath);
            orphan["WireGuardTunnelTransaction"] = new JsonObject { ["TaskId"] = Guid.NewGuid().ToString("N") }; ArchiveStore.WriteJson(statePath, orphan);
            Refuses(() => WireGuardTunnels.GuardOperation(f.Store, new(OperationKind.Recover, f.Relative(plans[0]), new())), "lost pair record allowed a single-host recovery");
            WireGuardTunnels.GuardOperation(f.Store, new(OperationKind.HealthAudit, f.Relative(plans[0]), new()));
        }
    }
    private sealed class WireGuardRemote : IRemoteSessionFactory
    {
        public Dictionary<string, WireGuardHostFake> Hosts { get; } = [];
        public Task<IRemoteSession> OpenAsync(SshEndpoint e, IUserInteraction u, CancellationToken ct) => Task.FromResult<IRemoteSession>(Hosts[e.Host]);
    }
    private sealed class WireGuardHostFake(string address, int index) : IRemoteSession
    {
        public FakeRemote Inner { get; } = new(); public JsonObject? Config { get; set; } private JsonObject? original;
        public string Failure { get; set; } = ""; public bool SameIdentity { get; set; } public int ApplyCalls { get; private set; } public int ProofStarts { get; private set; } public int ProofStops { get; private set; }
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => Inner.RunAsync(command, timeout, ct);
        public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken ct)
        {
            var asset = payload.Split('\n')[0].Replace("# MXH asset: ", "");
            string Parameter(string name) { var m = Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' "); return m.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(m.Groups[1].Value)) : ""; }
            static string Marker(string name, string value) => "VPSDEPLOY_" + name + "_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value)) + "\n";
            if (asset == "wireguard-read.sh") return new(0, Marker("WIREGUARD_STATE", new JsonObject { ["Hash"] = Failure == "drift" ? new string('f', 64) : Config == null ? "Absent" : ArchiveStore.Fingerprint(Config), ["Configuration"] = Config?.DeepClone(), ["Healthy"] = Config != null }.ToJsonString()) + "VPSDEPLOY_WIREGUARD_READ\n", "");
            if (asset == "wireguard-tools-install.sh") return new(0, "VPSDEPLOY_WIREGUARD_TOOLS_READY\n", "");
            if (asset == "wireguard-backup-proof.sh") return new(0, Marker("WIREGUARD_BACKUP_SHA256", (await Inner.RunAsync("sha256sum -- '" + Parameter("BACKUP_DIR") + "/protocol-files.tar.gz'", timeout, ct)).Output.Trim().Split(' ')[0]) + "VPSDEPLOY_WIREGUARD_BACKUP_PROOF\n", "");
            if (asset == "wireguard-key.sh") { if (Failure == "key-ack") throw new IOException("lost key acknowledgement"); return new(0, Marker("WIREGUARD_PUBLIC", Convert.ToBase64String(Enumerable.Repeat((byte)(index + 1), 32).ToArray())) + "VPSDEPLOY_WIREGUARD_KEY_READY\n", ""); }
            if (asset == "protocol-migration-arm-rollback.sh") { original = Config?.DeepClone().AsObject(); Inner.StatusTaskId = Parameter("CONTROL_TASK_ID"); Inner.StatusPhase = Failure == "arm-before" ? "Preparing" : "Armed"; if (Failure is "arm-before" or "arm-ack") throw new IOException("lost snapshot acknowledgement"); }
            if (asset == "wireguard-apply.sh") { ApplyCalls++; Config = Parameter("ACTION") == "Remove" ? null : JsonNode.Parse(Parameter("CONFIG_JSON"))!.AsObject(); if (Failure == "apply-ack") throw new IOException("lost apply acknowledgement"); return new(0, "VPSDEPLOY_WIREGUARD_APPLIED\n", ""); }
            if (asset == "wireguard-proof.sh")
            {
                if (Parameter("ACTION") == "proof-start") ProofStarts++;
                else if (Parameter("ACTION") == "proof-stop") ProofStops++;
                else
                {
                    if (Failure == "cancel") throw new OperationCanceledException();
                    if (Failure is "rollback" or "owner") throw new IOException("proof failed");
                    var proof = new JsonObject { ["Status"] = "Passed", ["TCP"] = true, ["UDP"] = Failure != "missing-udp", ["ResponseMatched"] = true, ["Scope"] = "WireGuardPeerApplication", ["ChallengeDigest"] = Failure == "stale" ? new string('f', 64) : ArchiveStore.Digest(Encoding.UTF8.GetBytes("may-wireguard:" + Parameter("PROOF_NONCE"))) };
                    return new(0, Marker("WIREGUARD_PROOF", proof.ToJsonString()) + "VPSDEPLOY_WIREGUARD_PROOF_DONE\n", "");
                }
                return new(0, "VPSDEPLOY_WIREGUARD_PROOF_DONE\n", "");
            }
            if (asset == "maintenance-transaction-commit.sh") { if (Failure == "commit-second") throw new IOException("commit failed"); Inner.StatusPhase = "Committed"; if (Failure is "commit-ack" or "compensation-ack") throw new IOException("lost commit acknowledgement"); }
            if (asset == "maintenance-transaction-status.sh" && Failure == "owner") Inner.StatusTaskId = new string('e', 32);
            if (asset is "protocol-migration-trigger-rollback.sh" or "wireguard-pair-rollback.sh")
            {
                if (Failure == "rollback") throw new IOException("recovery disconnected"); Config = original?.DeepClone().AsObject();
                if (asset == "wireguard-pair-rollback.sh") { Inner.StatusPhase = "WireGuardRolledBack"; if (Failure == "compensation-ack") throw new IOException("lost compensation acknowledgement"); return new(0, "VPSDEPLOY_WIREGUARD_PAIR_ROLLED_BACK\n", ""); }
            }
            return await Inner.RunScriptAsync(payload, timeout, mutation, ct);
        }
        public Task<byte[]> ReadFileAsync(string path, CancellationToken ct) => path == "/etc/machine-id" ? Task.FromResult(Encoding.ASCII.GetBytes(ArchiveStore.Digest(Encoding.ASCII.GetBytes(SameIdentity ? "192.0.2.40" : address))[..32])) : Inner.ReadFileAsync(path, ct);
        public Task DownloadAsync(string path, string target, CancellationToken ct) => Inner.DownloadAsync(path, target, ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
