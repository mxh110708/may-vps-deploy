using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunResource31Tests()
    {
        await Resource31Coverage();
        Console.WriteLine($"PASS: {assertions} resource, certificate, dependency, read-only and failure assertions; no production connections.");
    }
    private static JsonObject Certificate31(string key, DateTimeOffset now, string digest = "") => new()
    {
        ["Key"] = key, ["Status"] = "Observed", ["NotBefore"] = now.AddDays(-1), ["NotAfter"] = now.AddDays(60),
        ["Sha256"] = digest == "" ? new string('a', 64) : digest, ["HostnameMatches"] = true
    };
    private async Task Resource31Coverage()
    {
        using var f = new Fixture(repository); var now = DateTimeOffset.UtcNow;
        var p = f.Plan("Resource-31"); var relative = f.Relative(p);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials();
        var a = InboundCatalog.AddInbound(model, credentials, "AnyTLS"); var b = InboundCatalog.AddInbound(model, credentials, "Hysteria2");
        var certId = InboundCatalog.NewId(); var cert = new JsonObject { ["Id"] = certId, ["Name"] = "Shared TLS", ["Sha256"] = new string('a', 64), ["NotAfter"] = now.AddDays(60) };
        model["Certificates"]!.AsArray().Add(cert); a["CertificateId"] = certId; b["CertificateId"] = certId; b["Enabled"] = false;
        a["Options"]!["ServerName"] = "tls.example.test"; b["Options"]!["ServerName"] = "tls.example.test";
        p["InboundModel"] = model; p.Put("Import.Status", JsonValue.Create("Completed"));
        var state = new JsonObject { ["Inbounds"] = new JsonObject { ["RemoteHash"] = new string('b', 64) } };
        var audit = new JsonObject { ["Inbounds"] = new JsonObject { ["MatchesArchive"] = true } };
        var request = OperationsResources.CertificateRequest(p);
        Check(request["Items"]!.AsArray().Count == 2 && request.ToJsonString().Contains("inbound:" + b.Text("Id")), "Disabled consumers were omitted from the certificate request.");
        var response = new JsonObject { ["Version"] = 1, ["CollectedAt"] = now, ["Items"] = new JsonArray(Certificate31("inbound:" + a.Text("Id"), now), Certificate31("inbound:" + b.Text("Id"), now)) };
        var checkedResponse = OperationsResources.ValidateCertificates(request, response, now);
        state["ResourceObservation"] = OperationsResources.Observation(p, state, audit, checkedResponse, now);
        var nodeId = InboundCatalog.NewId(); var schemeId = InboundCatalog.NewId(); var groupId = InboundCatalog.NewId();
        var memberId = InboundCatalog.NewId();
        var group = new JsonObject { ["Id"] = groupId, ["Name"] = "Reusable", ["Category"] = "Group", ["Nodes"] = new JsonArray(new JsonObject { ["Id"] = memberId, ["Name"] = "Member", ["InboundOrigin"] = new JsonObject { ["Instance"] = relative, ["InboundId"] = a.Text("Id") } }) };
        var scheme = new JsonObject { ["Id"] = schemeId, ["Name"] = "Client", ["Category"] = "Scheme", ["Nodes"] = new JsonArray(new JsonObject { ["Id"] = nodeId, ["Name"] = "Client node", ["GroupOrigin"] = new JsonObject { ["Id"] = groupId, ["MemberId"] = memberId } }) };
        OperationsResourceOverview Build(DateTimeOffset? at = null, bool canMaintain = true) => OperationsResources.Build([new(relative, p, state, canMaintain)], at ?? now, clients: [group, scheme]);
        var view = Build(); var certKey = OperationsResources.Key(relative, "Certificate", certId);
        var resource = view.Items.Single(i => i.Key == certKey);
        Check(resource.Status == "Valid" && resource.Evidence == "Observed", "Matching public certificate observations did not produce a current result.");
        Check(view.Items.Where(i => i.Evidence == "Archive").All(i => i.ObservedAt == null), "Unprobed resources inherited an unrelated health audit timestamp.");
        Check(view.Consumers(certKey, false).Count == 2 && view.Consumers(certKey).Count == 4, "Shared certificates lost direct, disabled, reusable or scheme consumers.");
        Check(view.Consumers(certKey).Any(i => i.Status == "Disabled"), "Disabled consumers became removable or disappeared.");
        Check(view.RelatedKeys(relative).Contains(OperationsResources.NodeKey(schemeId, nodeId)), "The instance filter omitted indirect clients that only reference a reusable group.");
        Check(!view.Items.Any(i => i.Kind == "Certificate" && i.Name.Contains("Reality")), "An external Reality target became a locally managed certificate.");
        foreach (var (days, expected) in new[] { (-1d, "Expired"), (0d, "Expired"), (0.1d, "Expiring"), (14d, "Expiring"), (14.1d, "DueSoon"), (30d, "DueSoon"), (30.1d, "Valid") })
            Check(OperationsResources.Expiry("", now.AddDays(days).ToString("O"), now) == expected, "Expiration threshold was rounded or used a stale relative-day count.");
        Check(OperationsResources.Expiry(now.AddHours(1).ToString("O"), now.AddDays(60).ToString("O"), now) == "NotYetValid", "Future certificates were shown as valid.");
        foreach (var invalid in new[] { "", "unknown", "2026-02-31" }) Check(OperationsResources.Expiry("", invalid, now) == "Unknown", "Malformed expiry was accepted.");
        Check(Build(now.AddHours(24).AddSeconds(1)).Items.Single(i => i.Key == certKey).Evidence == "Stale", "A stale snapshot stayed current.");
        Check(Build(now.AddHours(25)).Items.Single(i => i.Key == certKey).NotAfter != null, "A stale snapshot discarded its clearly labelled last-known expiry.");
        Check(Build(now.AddDays(61)).Items.Single(i => i.Key == certKey).Status == "Expired", "Certificate expiry did not advance with the clock.");
        var before = p.DeepClone().AsObject(); a["Name"] = "changed";
        Check(Build().Items.Single(i => i.Key == certKey).Evidence == "Changed", "A changed archive reused old remote evidence.");
        p["InboundModel"] = before["InboundModel"]!.DeepClone();
        var changedReply = response.DeepClone().AsObject(); changedReply["Items"]![0]!["Sha256"] = new string('c', 64);
        state["ResourceObservation"] = OperationsResources.Observation(p, state, audit, changedReply, now);
        Check(Build().Items.Single(i => i.Key == certKey).Status == "Drift", "Different copies of one shared certificate were not identified.");
        foreach (var status in new[] { "Missing", "Unreadable" })
        {
            var broken = response.DeepClone().AsObject(); broken["Items"]![1] = new JsonObject { ["Key"] = "inbound:" + b.Text("Id"), ["Status"] = status };
            state["ResourceObservation"] = OperationsResources.Observation(p, state, audit, broken, now);
            Check(Build().Items.Single(i => i.Key == certKey).Status == status, "Missing/unreadable certificate was reported as valid.");
        }
        state["ResourceObservation"] = OperationsResources.Observation(p, state, audit, null, now);
        Check(Build().Items.Single(i => i.Key == certKey).Evidence == "Failed", "An incomplete fresh observation reused old certificate evidence.");
        Check(Build(canMaintain: false).Items.Where(i => i.Instance == relative && i.Kind is not ("ClientNode" or "ClientGroup")).All(i => i.Maintenance == "Instance"), "Pending or draft resources exposed direct mutation entrypoints.");
        foreach (var mutate in new Action<JsonObject>[]
        {
            r => r["Items"]!.AsArray().RemoveAt(0), r => r["Items"]!.AsArray().Add(r["Items"]![0]!.DeepClone()),
            r => r["Items"]![0]!["Key"] = "inbound:" + InboundCatalog.NewId(), r => r["Items"]![0]!["PrivateKey"] = "synthetic-secret",
            r => r["Items"]![0]!["Status"] = "Passed", r => r["Items"]![0]!["Sha256"] = "bad",
            r => r["Items"]![0]!["HostnameMatches"] = "true", r => r["CollectedAt"] = now.AddMinutes(10), r => r["CollectedAt"] = now.AddMinutes(-11), r => r["Version"] = 2
        }) { var bad = response.DeepClone().AsObject(); mutate(bad); Refuses(() => OperationsResources.ValidateCertificates(request, bad, now), "Unscoped, forged, incomplete or stale observation accepted."); }
        var cycle = new OperationsResourceOverview([new("a", "", "User", "a", "Recorded", "Archive", null, null, "", "", "", ["b"]), new("b", "", "User", "b", "Recorded", "Archive", null, null, "", "", "", ["a"])], []);
        Check(cycle.Consumers("a").Count == 1, "A cyclic impact graph did not terminate or included itself.");
        var secretDocument = new JsonObject { ["Id"] = schemeId, ["Name"] = "Redacted", ["ApiToken"] = "synthetic-token", ["Nodes"] = new JsonArray(new JsonObject { ["Id"] = nodeId, ["name"] = "node", ["sing_box"] = new JsonObject { ["password"] = "synthetic-password", ["tls"] = new JsonObject { ["certificate"] = "synthetic-pem" } }, ["InboundOrigin"] = new JsonObject { ["Instance"] = relative, ["InboundId"] = a.Text("Id"), ["Token"] = "synthetic-origin-secret" } }) };
        var metadata = OperationsResources.ClientMetadata(secretDocument, "Scheme");
        Check(!metadata.ToJsonString().Contains("synthetic-"), "Client impact metadata leaked authentication or certificate material.");
        f.SaveInstance(p); var root = f.Paths.Instance(relative); ArchiveStore.WriteJson(SafePath.Resolve(root, "deployment-state.json"), state);
        f.Store.WriteSecret(f.Paths.Resolve("private/client-schemes/" + schemeId + ".dotnet.private.json"), secretDocument);
        var beforeFiles = Directory.GetFiles(f.Paths.Private, "*", SearchOption.AllDirectories).ToDictionary(s => s, s => ArchiveStore.Digest(File.ReadAllBytes(s)));
        var loaded = OperationsResources.Load(f.Store, now);
        Check(loaded.Items.Any(i => i.Key == certKey), "Archive-backed overview lost the shared certificate.");
        Check(beforeFiles.Count == Directory.GetFiles(f.Paths.Private, "*", SearchOption.AllDirectories).Length && beforeFiles.All(pair => ArchiveStore.Digest(File.ReadAllBytes(pair.Key)) == pair.Value), "Reading the resource overview wrote archives or migrated client layouts.");
        foreach (var invalid in new JsonNode?[] { null, new JsonObject(), new JsonArray(new JsonObject { ["Id"] = "" }), new JsonArray(new JsonObject { ["Id"] = nodeId }, new JsonObject { ["Id"] = nodeId }) })
        {
            var bad = secretDocument.DeepClone().AsObject(); bad["Nodes"] = invalid?.DeepClone(); Refuses(() => OperationsResources.ClientMetadata(bad, "Scheme"), "Malformed client metadata was silently hidden or given a synthetic identity.");
        }
        f.Store.WriteSecret(f.Paths.Resolve("private/client-node-groups/" + groupId + ".dotnet.private.json"), new JsonObject { ["Id"] = groupId, ["Name"] = "Empty", ["Nodes"] = new JsonArray() });
        ArchiveStore.AtomicWrite(f.Paths.Resolve("private/client-schemes/" + InboundCatalog.NewId() + ".dotnet.private.json"), Encoding.UTF8.GetBytes("broken"));
        var partial = OperationsResources.Load(f.Store, now); Check(partial.Issues.Any() && partial.Items.Any(i => i.Key == certKey), "A corrupt protected source erased unrelated inventory or was silently ignored.");
        Resource31Graph(f, now);
        await Resource31Workflow();
    }
    private void Resource31Graph(Fixture f, DateTimeOffset now)
    {
        var p = f.Plan("Graph"); var relative = f.Relative(p); var relay = f.Relative(f.Plan("Relay")); var landing = f.Relative(f.Plan("Landing"));
        p.Put("Import.Status", JsonValue.Create("Completed"));
        var firstId = InboundCatalog.NewId(); var secondId = InboundCatalog.NewId();
        var first = WireGuardTunnels.New(relative); first["Id"] = firstId; first["SecondInstance"] = relay;
        var second = WireGuardTunnels.New(relay); second["Id"] = secondId; second["SecondInstance"] = landing;
        var c = TcpChains.New(relative); c["RelayInstance"] = relay; c["LandingInstance"] = landing; c["Landing"] = new JsonObject { ["SchemeId"] = InboundCatalog.NewId(), ["NodeId"] = InboundCatalog.NewId() };
        c["WireGuards"] = new JsonArray(new JsonObject { ["Id"] = firstId, ["Segment"] = "FrontRelay", ["Fingerprint"] = new string('a', 64) }, new JsonObject { ["Id"] = secondId, ["Segment"] = "RelayLanding", ["Fingerprint"] = new string('b', 64) });
        var active = new JsonObject { ["Configuration"] = c, ["Phase"] = "Active" };
        var t1 = new JsonObject { ["Configuration"] = first, ["Phase"] = "Active" }; var t2 = new JsonObject { ["Configuration"] = second, ["Phase"] = "Active" };
        var node = new JsonObject { ["Id"] = InboundCatalog.NewId(), ["Name"] = "Derived", ["TcpChainOrigin"] = new JsonObject { ["Id"] = c.Text("Id") } };
        var scheme = new JsonObject { ["Id"] = InboundCatalog.NewId(), ["Name"] = "Chain client", ["Category"] = "Scheme", ["Nodes"] = new JsonArray(node) };
        var view = OperationsResources.Build([new(relative, p, new(), true)], now, [active], [t1, t2], [scheme]);
        foreach (var id in new[] { firstId, secondId })
        {
            var consumers = view.Consumers(OperationsResources.TunnelKey(id));
            Check(consumers.Any(i => i.Kind == "Chain") && consumers.Any(i => i.Kind == "ClientNode"), "One of two adjacent channels lost its full chain/client impact.");
        }
        Check(view.Issues.Any(), "Missing mapped rules or upstream source references were silently ignored.");
        foreach (var phase in new[] { "Removed", "RolledBack" })
        {
            active["Phase"] = phase; t1["Phase"] = phase; t2["Phase"] = phase;
            var ended = OperationsResources.Build([new(relative, p, new(), true)], now, [active], [t1, t2]);
            Check(!ended.Items.Any(i => i.Kind is "Chain" or "WireGuard"), "Ended records were presented as installed resources.");
        }
        active["Phase"] = "Applying"; t1["Phase"] = "NeedsRecovery";
        var pending = OperationsResources.Build([new(relative, p, new(), false)], now, [active], [t1]);
        Check(pending.Items.Where(i => i.Kind is "Chain" or "WireGuard").All(i => i.Status == "Pending"), "Unconfirmed shared transactions were hidden as normal resources.");
    }
    private async Task Resource31Workflow()
    {
        foreach (var failure in new[] { "", "connection", "cancel", "unknown" })
        {
            using var f = new Fixture(repository); var p = f.Plan("Audit-" + (failure == "" ? "success" : failure));
            p["Role"] = "AnyTlsEntry"; p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("AnyTls.ServerName", JsonValue.Create("tls.example.test")); p.Put("AnyTls.EchPublicName", JsonValue.Create("outer.example.test"));
            p["Roles"] = new JsonArray("AnyTlsEntry"); p["ProtocolInventory"] = new JsonObject { ["AnyTlsEntry"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true }, ["RealityEntry"] = new JsonObject { ["Installed"] = false, ["Enabled"] = false } };
            f.SaveInstance(p); var relative = f.Relative(p); var baseline = File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json"));
            var remote = new FakeRemote(); remote.SeedProtocols(p); var adapter = new Resource31Remote(remote, failure);
            var workflow = new WorkflowEngine(f.Store, adapter, new FakeKeys(), new FakeUser(), new FakeValidation());
            try
            {
                await workflow.ExecuteAsync(new(OperationKind.HealthAudit, relative, new()), Guid.NewGuid().ToString("N"), new Progress<TaskProgress>(), CancellationToken.None);
                Check(failure != "cancel", "Cancellation was swallowed by the resource audit.");
            }
            catch (OperationCanceledException) { Check(failure == "cancel", "Unexpected audit cancellation."); }
            var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json"));
            Check(adapter.Calls == 1 && !adapter.Mutating && remote.Mutations == 0 && !remote.Commands.Any(c => c.Contains("rollback") || c.Contains("renew")), "Reading resources mutated remote services, replayed a command or renewed a certificate.");
            Check(File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json")).SequenceEqual(baseline), "Read-only resource collection rewrote encrypted credentials.");
            if (failure == "") Check(state.At("ResourceObservation.Certificates.Items") is JsonArray items && items.Count == 1 && state.Text("ResourceObservation.Identity") == OperationsResources.ObservationIdentity(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json")), state), "Fresh certificate evidence was not bound to the final archive identity.");
            if (failure is "connection" or "unknown") Check(state.At("ResourceObservation.Certificates") == null && OperationsResources.Load(f.Store, DateTimeOffset.UtcNow).Items.Where(i => i.Kind == "Certificate").All(i => i.Evidence == "Failed"), "Failed certificate collection kept a green current snapshot.");
        }
    }
    private sealed class Resource31Remote(FakeRemote inner, string failure) : IRemoteSessionFactory, IRemoteSession
    {
        public int Calls; public bool Mutating;
        public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction interaction, CancellationToken token) => Task.FromResult<IRemoteSession>(this);
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => inner.RunAsync(command, timeout, token);
        public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => inner.ReadFileAsync(path, token);
        public Task DownloadAsync(string path, string destination, CancellationToken token) => inner.DownloadAsync(path, destination, token);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken token)
        {
            if (!payload.StartsWith("# MXH asset: resource-certificates-read.sh\n", StringComparison.Ordinal)) return inner.RunScriptAsync(payload, timeout, mutating, token);
            Calls++; Mutating |= mutating;
            if (failure == "connection") throw new IOException("synthetic response lost");
            if (failure == "cancel") throw new OperationCanceledException();
            var now = DateTimeOffset.UtcNow; var item = Certificate31("anytls", now); if (failure == "unknown") item["PrivateKey"] = "synthetic-secret";
            var response = new JsonObject { ["Version"] = 1, ["CollectedAt"] = now, ["Items"] = new JsonArray(item) };
            return Task.FromResult(new CommandResult(0, "VPSDEPLOY_RESOURCE_CERTIFICATES_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(response.ToJsonString())) + "\nVPSDEPLOY_RESOURCE_READ_OK\n", ""));
        }
    }
}
