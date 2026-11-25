using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunInstanceAddress39Tests()
    {
        await InstanceAddress39Model(); await InstanceAddress39Workflow(); await InstanceAddress39MultiHost(); InstanceAddress39Underlays();
        await InstanceAddress39Programs();
        Console.WriteLine($"PASS: {assertions} address identity, dependency, review, transaction and recovery assertions; synthetic transports only.");
    }
    private async Task InstanceAddress39Programs()
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); if (string.IsNullOrEmpty(python)) return;
        using var f = new Fixture(repository); var assets = new RemoteAssets(f.Paths); var program = assets.AddressProgram();
        var document = new JsonObject { ["Task"] = new string('a', 32), ["ProgramSha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes(program)), ["Addresses"] = new JsonObject { ["192.0.2.10"] = "192.0.2.11" }, ["Resources"] = new JsonArray() };
        var payload = assets.Payload("instance-address.sh", new Dictionary<string, string> { ["ADDRESS_ACTION"] = "Inspect", ["ADDRESS_DOCUMENT"] = document.ToJsonString() });
        var embedded = System.Text.RegularExpressions.Regex.Match(payload, "MAY_ADDRESS_PROGRAM_B64'\\r?\\n([A-Za-z0-9+/=]+)").Groups[1].Value;
        Check(Encoding.UTF8.GetString(Convert.FromBase64String(embedded)) == program, "rendered address payload changed the reviewed program bytes");
        var loader = payload.Split("python3 - <<'MAY_ADDRESS_LAUNCHER'\n", StringSplitOptions.None)[1].Split("\nMAY_ADDRESS_LAUNCHER", StringSplitOptions.None)[0];
        foreach (var (name, code) in new[] { ("address-program.py", program), ("address-loader.py", loader) })
        {
            var path = f.Paths.Resolve(name); File.WriteAllText(path, code, new UTF8Encoding(false));
            var start = new System.Diagnostics.ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { "-I", "-m", "py_compile", path }) start.ArgumentList.Add(argument);
            using var process = System.Diagnostics.Process.Start(start)!; var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(); await output; await error; Check(process.ExitCode == 0, "rendered address Python program did not compile");
        }
    }
    private static JsonObject Address39Plan(Fixture f, string name, string ip)
    {
        var plan = f.Plan(name); plan.Put("Server.IPv4", JsonValue.Create(ip)); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var file = f.Paths.Resolve("private/ssh-hosts.dotnet.json"); var trust = File.Exists(file) ? ArchiveStore.ReadJson(file) : new JsonObject();
        trust[ArchiveStore.Digest(Encoding.UTF8.GetBytes(ip))] = Address39Remote.Pin; ArchiveStore.WriteJson(file, trust); return plan;
    }
    private async Task InstanceAddress39Model()
    {
        using var f = new Fixture(repository); var plan = Address39Plan(f, "AddressEntry", "192.0.2.10"); var relative = f.Relative(plan);
        var o = InstanceAddressChanges.Options(plan); o["IPv4"] = "192.0.2.11"; var request = new OperationRequest(OperationKind.InstanceAddress, relative, o);
        var land = Address39Plan(f, "AddressLanding", "198.51.100.20"); land.Put("Shadowsocks.TrustedEntryIPv4s", new JsonArray("192.0.2.10", "192.0.2.199"));
        ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(land)), "deployment-plan.json"), land);
        var before = File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"));
        var preview = InstanceAddressChanges.Prepare(f.Store, request);
        Check(preview.Document["Hosts"]!.AsArray().Count == 2, "landing whitelist dependency was omitted");
        var affected = preview.Document["Hosts"]!.AsArray().Single(h => h!.Text("Instance") == f.Relative(land))!;
        Check(affected.Strings("After.Shadowsocks.TrustedEntryIPv4s").SequenceEqual(new[] { "192.0.2.11", "192.0.2.199" }), "unrelated source or replacement was lost");
        Check(affected["Resources"]!.AsArray().Any(r => r!.Text("Kind") == "Firewall"), "persistent/runtime firewall scope absent");
        Check(before.SequenceEqual(File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"))), "preview changed the source archive");
        Check(InstanceAddressChanges.Prepare(f.Store, request).Fingerprint == preview.Fingerprint, "preview is not deterministic");
        Check(InstanceAddressChanges.Pending(new JsonObject { ["AddressChangeTransaction"] = new JsonObject() }) && InstanceAddressChanges.Pending(new JsonObject { ["AddressChangeTransaction"] = true }), "malformed pending address marker was ignored");
        var values = new JsonObject { ["Endpoint"] = "[2001:db8::10]:9000", ["server"] = "192.0.2.10", ["servername"] = "192.0.2.10", ["Name"] = "192.0.2.10", ["AllowedSources"] = new JsonArray("192.0.2.10/32", "192.0.2.0/24") };
        var map = new JsonObject { ["192.0.2.10"] = "192.0.2.11", ["2001:db8::10"] = "2001:db8::11" }; InstanceAddressChanges.Rewrite(values, map);
        Check(values.Text("Endpoint") == "[2001:db8::11]:9000", "IPv6 endpoint port was corrupted");
        Check(values.Text("servername") == "192.0.2.10" && values.Text("Name") == "192.0.2.10", "TLS identity or display name was rewritten");
        Check(values.Strings("AllowedSources").SequenceEqual(new[] { "192.0.2.11/32", "192.0.2.0/24" }), "broad CIDR was rewritten");
        var bridge = new JsonObject { ["AllowedSources"] = new JsonArray("192.0.2.10") }; InstanceAddressChanges.Rewrite(bridge, map, true);
        Check(bridge.Strings("AllowedSources").SequenceEqual(new[] { "192.0.2.10", "192.0.2.11" }), "transitional whitelist is incomplete");
        foreach (var ip in new[] { "127.0.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.11;id", "2001:db8::11" })
        { var invalid = o.DeepClone().AsObject(); invalid["IPv4"] = ip; Refuses(() => InstanceAddressChanges.Validate(request with { Options = invalid }), "invalid management address accepted"); }
        Refuses(() => InstanceAddressChanges.Prepare(f.Store, request with { Options = InstanceAddressChanges.Options(plan) }), "unchanged address accepted");
        var unknown = o.DeepClone().AsObject(); unknown["SkipIdentity"] = true; Refuses(() => InstanceAddressChanges.Validate(request with { Options = unknown }), "identity bypass option accepted");
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
        land["NodeName"] = "externally changed"; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(land)), "deployment-plan.json"), land);
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None), "review ignored a dependency change");
        File.Delete(f.Paths.Resolve("private/ssh-hosts.dotnet.json")); Refuses(() => InstanceAddressChanges.Prepare(f.Store, request), "unknown original host identity accepted");

        using var sources = new Fixture(repository); var sourcePlan = Address39Plan(sources, "AddressSource", "192.0.2.30"); var sourceId = Guid.NewGuid().ToString("N");
        var pair = ClientProfiles.Nodes(sourcePlan, sources.Store.ReadSecret(SafePath.Resolve(sources.Paths.Instance(sources.Relative(sourcePlan)), "secrets.dotnet.private.json"))).First();
        var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "My own name", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(sources.Relative(sourcePlan), pair) };
        var external = node.DeepClone().AsObject(); external.Remove("ManagedOrigin"); external["Id"] = Guid.NewGuid().ToString("N"); external["name"] = "External";
        var scheme = new JsonObject { ["Id"] = sourceId, ["Name"] = "AddressScheme", ["Nodes"] = new JsonArray(node, external), ["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" }, ["ExportTargets"] = new JsonObject { ["Clash"] = "external.yaml" } };
        var path = sources.Paths.Resolve("private/client-schemes/" + sourceId + ".dotnet.private.json"); sources.Store.WriteSecret(path, scheme);
        var options = InstanceAddressChanges.Options(sourcePlan); options["IPv4"] = "192.0.2.31";
        var prepared = InstanceAddressChanges.Prepare(sources.Store, new(OperationKind.InstanceAddress, sources.Relative(sourcePlan), options));
        var change = prepared.Document["Files"]!.AsArray().Single(p => p!.Text("Path").StartsWith("client-schemes/"))!["After"]!;
        var managed = change["Nodes"]!.AsArray()[0]!;
        Check(managed.Text("name") == "My own name" && managed.Text("Id") == node.Text("Id"), "node identity or custom name was lost");
        Check(managed.Text("sing_box.server") == "192.0.2.31" && managed.Text("ManagedOrigin.Fingerprint") != node.Text("ManagedOrigin.Fingerprint"), "managed origin did not refresh");
        Check(change["Candidate"] == null && change.Text("ExportTargets.Clash") == "external.yaml", "old validated candidate survived or export location changed");
        Check(change["Nodes"]!.AsArray()[1]!.Text("sing_box.server") == "192.0.2.30", "external source was silently adopted");
        Check(prepared.Document["Notices"]!.AsArray().Count > 0, "external impact was omitted");
        node["sing_box"]!["password"] = "synthetic local credential edit"; sources.Store.WriteSecret(path, scheme);
        Refuses(() => InstanceAddressChanges.Prepare(sources.Store, new(OperationKind.InstanceAddress, sources.Relative(sourcePlan), options)), "address change overwrote a managed node's local credentials");
    }
    private async Task InstanceAddress39Workflow()
    {
        foreach (var mode in new[] { "success", "lost-apply", "fail-apply", "cancel", "identity", "local-drift", "late-local-drift" })
        {
            using var f = new Fixture(repository); var plan = Address39Plan(f, "WorkflowAddress", "192.0.2.80"); var relative = f.Relative(plan); var options = InstanceAddressChanges.Options(plan); options["IPv4"] = "192.0.2.81";
            var request = new OperationRequest(OperationKind.InstanceAddress, relative, options); using var cancel = new CancellationTokenSource();
            var remote = new Address39Remote { Mode = mode, Cancel = cancel };
            var planFile = SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"); var stateFile = SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json");
            var originalPlan = File.ReadAllBytes(planFile); var originalState = File.ReadAllBytes(stateFile);
            if (mode == "local-drift") remote.AfterApply = () => { var edited = ArchiveStore.ReadJson(planFile); edited["NodeName"] = "external edit during operation"; ArchiveStore.WriteJson(planFile, edited); };
            if (mode == "late-local-drift") remote.AfterFinalStatus = () => { var edited = ArchiveStore.ReadJson(planFile); edited["NodeName"] = "external edit during operation"; ArchiveStore.WriteJson(planFile, edited); };
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation()); var coordinator = new TaskCoordinator(f.Store, engine);
            var reviewed = coordinator.Review(request); var result = await coordinator.ExecuteAsync(reviewed, request, new InlineProgress<TaskProgress>(_ => { }), cancel.Token);
            if (mode is "success" or "lost-apply")
            {
                Check(result.Outcome == (mode == "success" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), mode + " did not complete: " + result.Outcome + " / " + result.ErrorCode + " / " + result.SafeError + " / " + string.Join(',', remote.Actions));
                Check(ArchiveStore.ReadJson(planFile).Text("Server.IPv4") == "192.0.2.81", "committed address not archived");
                Check(!InstanceLifecycle.Read(f.Store, relative, ArchiveStore.ReadJson(planFile)).NeedsRecovery, "committed operation remained pending");
                Check(remote.Actions.Count(a => a == "Apply") == 1, "lost acknowledgement repeated a mutation");
                Check(remote.Actions.IndexOf("Bridge") < remote.Actions.IndexOf("Apply") && remote.Actions.IndexOf("Finalize") > remote.Actions.IndexOf("Apply"), "whitelist transition order changed");
            }
            else if (mode == "identity")
            {
                Check(result.Outcome == TaskOutcome.Failed && remote.Actions.Count == 0, "identity mismatch reached remote mutation");
                Check(originalPlan.SequenceEqual(File.ReadAllBytes(planFile)), "identity failure changed the plan");
            }
            else if (mode is "local-drift" or "late-local-drift")
            {
                Check(result.Outcome == TaskOutcome.NeedsRecovery, "foreign local edit was overwritten");
                Check(ArchiveStore.ReadJson(planFile).Text("NodeName") == "external edit during operation", "foreign edit was lost during recovery");
                var pending = ArchiveStore.ReadJson(stateFile).Text("AddressChangeTransaction.Id");
                Check(pending.Length == 32, "failed recovery was not discoverable on the original instance");
                var recovery = new OperationRequest(OperationKind.InstanceAddress, relative, new() { ["Action"] = "Recover", ["Id"] = pending });
                var journalFile = InstanceAddressChanges.RecordFile(f.Paths, pending); var journal = f.Store.ReadSecret(journalFile);
                journal["LocalFiles"]!["client-template-catalog.json"] = new JsonObject { ["BeforeHash"] = "Absent", ["CurrentHash"] = "Absent" };
                f.Store.WriteSecret(journalFile, journal);
                Refuses(() => InstanceAddressChanges.Prepare(f.Store, recovery), "forged local recovery scope accepted");
            }
            else
            {
                Check(result.Outcome == (mode == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "failed/cancelled transaction outcome incorrect");
                Check(originalPlan.SequenceEqual(File.ReadAllBytes(planFile)) && originalState.SequenceEqual(File.ReadAllBytes(stateFile)), "scoped restore changed original archive bytes");
                Check(remote.Actions.Contains("Rollback") && remote.Actions.Count(a => a == "Apply") <= 1, "recovery replayed an address apply");
            }
            Check(remote.Endpoints.All(e => e.ExpectedHostFingerprint == Address39Remote.Pin && e.Host == "192.0.2.81"), "SSH/SFTP connection did not retain original host pin or new recovery address");
        }
    }
    private async Task InstanceAddress39MultiHost()
    {
        foreach (var fail in new[] { false, true })
        {
            using var f = new Fixture(repository); var entry = Address39Plan(f, "MultiAddressEntry", "192.0.2.110"); var land = Address39Plan(f, "MultiAddressLanding", "198.51.100.110");
            land.Put("Shadowsocks.TrustedEntryIPv4s", new JsonArray("192.0.2.110")); var landPath = SafePath.Resolve(f.Paths.Instance(f.Relative(land)), "deployment-plan.json"); ArchiveStore.WriteJson(landPath, land); var before = File.ReadAllBytes(landPath);
            var options = InstanceAddressChanges.Options(entry); options["IPv4"] = "192.0.2.111";
            var request = new OperationRequest(OperationKind.InstanceAddress, f.Relative(entry), options);
            var remote = new Address39Remote { Mode = fail ? "fail-apply" : "success", FailHost = "198.51.100.110" };
            var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation()));
            var result = await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None);
            Check(result.Outcome == (fail ? TaskOutcome.Failed : TaskOutcome.Completed), "multi-host address result incorrect: " + result.SafeError);
            Check(remote.Endpoints.Select(e => e.Host).Distinct().Count() == 2, "whitelist peer was not locked and contacted");
            if (fail) { Check(before.SequenceEqual(File.ReadAllBytes(landPath)), "peer failure left its new whitelist in the archive"); Check(remote.Actions.Count(a => a == "Rollback") == 2, "peer failure did not restore both attempted hosts"); }
            else Check(ArchiveStore.ReadJson(landPath).Strings("Shadowsocks.TrustedEntryIPv4s").SequenceEqual(new[] { "192.0.2.111" }), "peer whitelist was not committed");
        }
    }
    private void InstanceAddress39Underlays()
    {
        using var f = new Fixture(repository); var remote = new ChainRemote(); var plans = new List<JsonObject>();
        for (var i = 0; i < 3; i++)
        {
            var p = Address39Plan(f, "UnderlayAddress" + i, "192.0.2." + (120 + i)); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (50 + i))); f.SaveInstance(p); plans.Add(p);
            remote.Hosts[p.Text("Server.IPv4")] = new ChainHost(p.Text("Server.IPv4"), remote);
        }
        var chain = TcpChains.New(f.Relative(plans[0])); chain["RelayInstance"] = f.Relative(plans[1]); chain["LandingInstance"] = f.Relative(plans[2]); chain["FrontSourceAddress"] = plans[0].Text("Server.IPv4");
        SeedChain30Underlays(f, plans, remote, chain);
        ArchiveStore.WriteJson(TcpChains.FileName(f.Paths, chain.Text("Id")), new JsonObject { ["Version"] = 1, ["Phase"] = "Active", ["Configuration"] = chain.DeepClone() });
        var target = TcpChains.Plan(f.Store, f.Relative(plans[1])); var options = InstanceAddressChanges.Options(target); options["IPv4"] = "192.0.2.151"; options["IPv6"] = "2001:db8::d1";
        var preview = InstanceAddressChanges.Prepare(f.Store, new(OperationKind.InstanceAddress, f.Relative(target), options));
        Check(preview.Document["Hosts"]!.AsArray().Count == 3, "adjacent WireGuard topology omitted an unchanged participant");
        var relay = preview.Document["Hosts"]!.AsArray().Single(h => h!.Text("Instance") == f.Relative(target))!;
        Check(relay["Resources"]!.AsArray().Count(r => r!.Text("Kind").StartsWith("WireGuardTunnel")) == 2, "one WireGuard slot was omitted from the same address transaction");
        var nextChain = preview.Document["Files"]!.AsArray().Single(v => v!.Text("Path").StartsWith("tcp-chains/"))!["After"]!["Configuration"]!;
        Check(nextChain["WireGuards"]!.AsArray().All(r => chain["WireGuards"]!.AsArray().All(old => old!.Text("Fingerprint") != r!.Text("Fingerprint"))), "a changed adjacent tunnel kept its old dependency fingerprint");
        var values = new JsonObject { ["FrontSourceAddress"] = "192.0.2.120", ["FrontSources"] = new JsonArray("192.0.2.120/32", "192.0.2.0/24") }; InstanceAddressChanges.Rewrite(values, new JsonObject { ["192.0.2.120"] = "192.0.2.160" });
        Check(values.Text("FrontSourceAddress") == "192.0.2.160" && values.Strings("FrontSources").SequenceEqual(new[] { "192.0.2.160/32", "192.0.2.0/24" }), "chain source and caller whitelist were not rewritten by typed identity");
    }
}

internal sealed class Address39Remote : IRemoteSessionFactory
{
    public static string Pin => "SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("address39 synthetic host"))).TrimEnd('=');
    public string Mode { get; init; } = "success";
    public CancellationTokenSource? Cancel { get; init; }
    public Action? AfterApply { get; set; }
    public Action? AfterFinalStatus { get; set; }
    public string? FailHost { get; init; }
    public List<string> Actions { get; } = [];
    public List<SshEndpoint> Endpoints { get; } = [];
    private readonly Dictionary<string, string> phases = new();
    private bool failed;
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken token)
    { token.ThrowIfCancellationRequested(); Endpoints.Add(endpoint); if (Mode == "identity") throw new OperationException("Synthetic identity mismatch.", code: "AddressHostIdentityChanged"); return Task.FromResult<IRemoteSession>(new Session(this, endpoint.Host)); }
    private sealed class Session(Address39Remote owner, string host) : IRemoteSession
    {
        private static string Marker(string key, string text) => "VPSDEPLOY_" + key + "_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(text)) + "\n";
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => Task.FromResult(new CommandResult(0, "", ""));
        public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (payload.StartsWith("# MXH asset: audit.sh", StringComparison.Ordinal)) return Task.FromResult(new CommandResult(0, Marker("OS_ID", "debian") + Marker("OS_VERSION", "13") + Marker("ARCH", "x86_64"), ""));
            if (payload.StartsWith("# MXH asset: firewall-preflight.sh", StringComparison.Ordinal)) return Task.FromResult(new CommandResult(0, "VPSDEPLOY_FIREWALL_SCOPE_OK\n", ""));
            if (!payload.StartsWith("# MXH asset: instance-address.sh", StringComparison.Ordinal)) return Task.FromResult(new CommandResult(0, "VPSDEPLOY_SSH_OK\n", ""));
            var match = System.Text.RegularExpressions.Regex.Match(payload, "export VPS_PARAM_ADDRESS_ACTION='([A-Za-z]+)'"); var action = match.Groups[1].Value; owner.Actions.Add(action);
            if (action == "Apply" && owner.Mode == "fail-apply" && !owner.failed && (owner.FailHost == null || owner.FailHost == host)) { owner.failed = true; throw new IOException("synthetic pre-apply transport loss"); }
            if (action == "Prepare") owner.phases[host] = "Prepared";
            else if (action == "Rollback") owner.phases[host] = "RolledBack";
            else if (action == "Commit") owner.phases[host] = "Committed";
            else if (action is "Bridge" or "Apply" or "Finalize") owner.phases[host] = action;
            if (action == "Status" && owner.phases.GetValueOrDefault(host) == "Finalize") { owner.AfterFinalStatus?.Invoke(); owner.AfterFinalStatus = null; }
            if (action == "Apply") { owner.AfterApply?.Invoke(); if (owner.Mode == "lost-apply" && !owner.failed) { owner.failed = true; throw new IOException("synthetic lost acknowledgement after apply"); } }
            if (action == "Bridge" && owner.Mode == "cancel") owner.Cancel!.Cancel();
            var docMatch = System.Text.RegularExpressions.Regex.Match(payload, "MAY_ADDRESS_DOCUMENT_B64'\\r?\\n([A-Za-z0-9+/=]+)");
            var doc = JsonNode.Parse(Convert.FromBase64String(docMatch.Groups[1].Value))!.AsObject(); var hashes = new JsonObject(); foreach (var resource in doc["Resources"]!.AsArray()) hashes[resource!.Text("Kind")] = new string('f', 64);
            var value = new JsonObject { ["Phase"] = action == "Inspect" ? "Inspected" : owner.phases.GetValueOrDefault(host, "Absent"), ["Consistent"] = true, ["Hashes"] = hashes, ["Observations"] = new JsonObject() };
            return Task.FromResult(new CommandResult(0, Marker("ADDRESS_STATE", value.ToJsonString()) + "VPSDEPLOY_ADDRESS_OK\n", ""));
        }
        public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => throw new OperationException("Unexpected synthetic file read.");
        public Task DownloadAsync(string source, string destination, CancellationToken token) => throw new OperationException("Unexpected synthetic download.");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
