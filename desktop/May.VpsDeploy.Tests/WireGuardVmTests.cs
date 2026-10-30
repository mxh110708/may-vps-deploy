using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunWireGuardVmTests(string manifestFile)
    {
        if (!Path.GetFullPath(manifestFile).Contains(Path.DirectorySeparatorChar + ".codex-tmp" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new Exception("Disposable fixture required.");
        var manifest = ArchiveStore.ReadJson(manifestFile);
        if (!manifest.Flag("SyntheticOnly") || manifest["Nodes"] is not JsonObject { Count: 2 } nodes || nodes["Front"] == null || nodes["Relay"] == null) throw new Exception("Two disposable guests required.");
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(8)); var ct = budget.Token;
        var factory = new TcpChainVmFactory(f.Store, nodes); var user = new FakeUser(); var plans = new List<JsonObject>();
        async Task<IRemoteSession> Connect(int index) { var host = nodes[index == 0 ? "Front" : "Relay"]!; return await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, ct); }
        async Task<string> Read(int index, string command) { await using var session = await Connect(index); var response = await session.RunAsync(command, TimeSpan.FromSeconds(25), ct); response.RequireSuccess("Disposable WireGuard observation failed."); return response.Output.Trim(); }
        var evidence = new JsonArray();
        foreach (var name in new[] { "Front", "Relay" })
        {
            var host = nodes[name]!; var index = plans.Count;
            var identity = (await Read(index, "python3 -c \"from pathlib import Path; print(Path('/etc/may-tcp-chain-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\"")).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            Check(identity.Length == 2 && identity.All(v => v.Equals(host.Text("FixtureId"), StringComparison.OrdinalIgnoreCase)), "guest identity mismatch before mutation");
            var p = f.Plan("WireGuard22VM-" + name); p["Role"] = "MonitorOnly"; p["Roles"] = new JsonArray("MonitorOnly"); p["ActiveEntry"] = ""; p["AdminUser"] = "root";
            p["ProtocolInventory"] = new JsonObject(); foreach (var role in DeploymentPlans.Roles[..3]) p["ProtocolInventory"]![role] = new JsonObject { ["Installed"] = false, ["Enabled"] = false };
            p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Import.SshAuthenticationPreserved", JsonValue.Create(true));
            p.Put("Server.IPv4", JsonValue.Create(host.Text("Address"))); p.Put("Server.IPv6", JsonValue.Create(host.Text("IPv6")));
            p.Put("Ports.SshPrimary", JsonValue.Create(22)); p.Put("Ports.SshRescue", JsonValue.Create(2222)); p.Put("Server.BootstrapSshPort", JsonValue.Create(22));
            p.Put("SshKey.SourcePrivateKeyPath", JsonValue.Create(host.Text("KeyFile"))); p.Put("Firewall.Mode", JsonValue.Create("ManagedNftables")); f.SaveInstance(p); plans.Add(p);
            await using var session = await Connect(index);
            var asset = new RemoteAssets(f.Paths).Payload("nftables-apply.sh", new Dictionary<string, string> { ["TCP_PORTS"] = "22,2222", ["UDP_PORTS"] = "" });
            (await session.RunScriptAsync(asset, TimeSpan.FromSeconds(25), true, ct)).RequireSuccess("Disposable managed firewall baseline failed.");
        }
        var preserved = new string[2];
        // Router-advertisement lease expiry naturally counts down. Compare the
        // route identity, gateway, device, metric and rules, not that countdown.
        const string scopeRead = "sha256sum /etc/resolv.conf; ip -4 route show default; ip -6 route show default | sed -E 's/ expires [0-9]+sec//'; ip -4 rule show; ip -6 rule show; sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding";
        for (var i = 0; i < 2; i++) preserved[i] = await Read(i, scopeRead);
        foreach (var family in new[] { "IPv4", "IPv6" })
        {
            Console.WriteLine("START: actual WireGuard " + family);
            var c = WireGuardTunnels.New(f.Relative(plans[0])); c["SecondInstance"] = f.Relative(plans[1]); c["Family"] = family; if (family == "IPv6") c["KeepaliveSeconds"] = 25;
            var engine = new WorkflowEngine(f.Store, factory, new FakeKeys(), user, new FakeValidation()); var coordinator = new TaskCoordinator(f.Store, engine);
            OperationRequest Request(string action) => new(OperationKind.WireGuardTunnel, f.Relative(plans[0]), new() { ["Action"] = action, ["Configuration"] = c.DeepClone() });
            async Task<TaskRecord> Execute(string action) { var r = Request(action); return await coordinator.ExecuteAsync(coordinator.Review(r), r, new InlineProgress<TaskProgress>(_ => { }), ct); }
            var applied = await Execute("Apply"); Check(applied.Outcome == TaskOutcome.Completed, "actual WireGuard creation failed: " + applied.SafeError);
            var record = ArchiveStore.ReadJson(WireGuardTunnels.FileName(f.Paths, c.Text("Id")));
            Check(record["Validation"]!["Directions"]!.AsArray().Count == 2, "actual bidirectional proof missing");
            Check((await Execute("Check")).Outcome == TaskOutcome.Completed, "actual WireGuard TCP/UDP recheck failed");
            for (var i = 0; i < 2; i++)
            {
                Check(await Read(i, scopeRead) == preserved[i], "WireGuard changed default routing, DNS or forwarding sysctls");
                Check(await Read(i, "test ! -e /var/lib/may-vps-deploy/transaction.owner && ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer && systemctl is-active --quiet may-wireguard.service && printf CLEAN") == "CLEAN", "actual committed tunnel retained owner/timer or stopped");
                Check((await Read(i, "stat -c '%a' /etc/may-vps-deploy-wireguard/private.key")).Trim() == "600", "private key mode is not 0600");
                Check(await Read(i, "systemctl show may-wireguard.service -p MainPID --value") == "0", "WireGuard introduced a resident userspace daemon");
            }
            if (family == "IPv4")
            {
                Console.WriteLine("START: actual WireGuard reboot persistence");
                for (var i = 0; i < 2; i++)
                {
                    var bootBefore = await Read(i, "cat /proc/sys/kernel/random/boot_id");
                    await Read(i, "systemd-run --quiet --on-active=1 /usr/sbin/reboot");
                    var ready = false;
                    for (var attempt = 0; attempt < 25; attempt++)
                    {
                        try { var observed = await Read(i, "cat /proc/sys/kernel/random/boot_id; systemctl is-active --quiet may-wireguard.service && systemctl is-active --quiet may-tcp-chain-network.service && printf READY"); ready = observed.EndsWith("READY", StringComparison.Ordinal) && !observed.Contains(bootBefore, StringComparison.Ordinal); } catch (Exception) when (!ct.IsCancellationRequested) { }
                        if (ready) break; await Task.Delay(1000, ct);
                    }
                    Check(ready, "WireGuard did not return after guest reboot");
                }
                var postReboot = await Execute("Check"); Check(postReboot.Outcome == TaskOutcome.Completed, "actual post-reboot bidirectional business proof failed: " + postReboot.SafeError);
            }
            if (family == "IPv4")
            {
                Console.WriteLine("START: actual interrupted removal restores live keys, directory permissions and both peers");
                factory.Fault = "relay-commit-ack";
                var failedRemoval = await Execute("Remove"); Check(failedRemoval.Outcome == TaskOutcome.Failed, "interrupted removal was not compensated: " + failedRemoval.SafeError);
                Check((await Execute("Check")).Outcome == TaskOutcome.Completed, "actual restored removal could not pass business traffic");
                for (var i = 0; i < 2; i++) Check(await Read(i, "stat -c '%a' /etc/may-vps-deploy-wireguard") == "700", "restored private key directory has incorrect mode");
            }
            var removed = await Execute("Remove"); Check(removed.Outcome == TaskOutcome.Completed, "actual WireGuard removal failed: " + removed.SafeError);
            for (var i = 0; i < 2; i++)
                Check(await Read(i, "test ! -e /etc/may-vps-deploy-wireguard && test ! -e /etc/systemd/system/may-wireguard.service && test ! -e /usr/local/libexec/may-wireguard && test ! -e /var/lib/may-vps-deploy/transaction.owner && ! ip link show maywg0 >/dev/null 2>&1 && ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer && printf CLEAN") == "CLEAN", "actual removal left owned tunnel resources");
            evidence.Add(new JsonObject { ["Family"] = family, ["Validation"] = record["Validation"]!.DeepClone(), ["RemovedAndClean"] = true, ["RebootedBothGuests"] = family == "IPv4" });
            if (family == "IPv6")
            {
                Console.WriteLine("START: actual WireGuard lost commit acknowledgement compensation");
                c["Id"] = Guid.NewGuid().ToString("N"); factory.Fault = "relay-commit-ack";
                var failed = await Execute("Apply"); Check(failed.Outcome == TaskOutcome.Failed && factory.LostAcknowledgements == 2, "actual lost commit was replayed or not compensated: " + failed.SafeError);
                for (var i = 0; i < 2; i++) Check(await Read(i, "test ! -e /etc/may-vps-deploy-wireguard && test ! -e /var/lib/may-vps-deploy/transaction.owner && ! ip link show maywg0 >/dev/null 2>&1 && printf CLEAN") == "CLEAN", "committed peer was not compensated");
                c["Id"] = Guid.NewGuid().ToString("N"); factory.Fault = "wireguard-udp-proof";
                try
                {
                    var blocked = await Execute("Apply"); Check(blocked.Outcome == TaskOutcome.Failed, "TCP-only success hid a blocked inner UDP response: " + blocked.SafeError);
                    Check(await Read(0, "nft list table inet may_fixture_wg_udp_block >/dev/null && test ! -e /etc/may-vps-deploy-wireguard && test ! -e /var/lib/may-vps-deploy/transaction.owner && printf SCOPED") == "SCOPED", "failed UDP proof did not restore its own scope or removed the independent interruption table");
                    Check(await Read(1, "test ! -e /etc/may-vps-deploy-wireguard && test ! -e /var/lib/may-vps-deploy/transaction.owner && printf CLEAN") == "CLEAN", "blocked UDP proof left the other peer installed");
                }
                finally { await Read(0, "nft delete table inet may_fixture_wg_udp_block"); }
            }
        }
        ArchiveStore.WriteJson(Path.Combine(Path.GetDirectoryName(manifestFile)!, "round22-result.json"), new JsonObject { ["Status"] = "Passed", ["Assertions"] = assertions, ["Cases"] = evidence, ["ProductionTargets"] = false, ["HostRoutesChanged"] = false, ["LostCommitAcknowledgements"] = factory.LostAcknowledgements });
        Console.WriteLine($"PASS: {assertions} actual two-guest WireGuard IPv4/IPv6, bidirectional applications, reboot, no-scope-change and commit-compensation assertions.");
    }
}
