using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed class Fixture : IDisposable
{
    public string Root { get; }
    public AppPaths Paths { get; }
    public ArchiveStore Store { get; }
    public JsonObject Versions => ArchiveStore.ReadJson(Paths.Resolve("config/versions.json"));
    public Fixture(string repository)
    {
        Root = Path.Combine(repository, ".test-output", "dotnet-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Root); Paths = new(Root); Store = new(Paths, new TestProtector());
        foreach (var name in new[] { "assets/remote", "assets/kernel", "config", "templates/client", "scripts" }) { var source = Path.Combine(repository, name); foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).Where(p => !p.EndsWith(".local.json", StringComparison.OrdinalIgnoreCase) && !p.Contains("__pycache__", StringComparison.Ordinal))) { SafePath.CheckLinks(file); var target = Paths.Resolve(name + "/" + Path.GetRelativePath(source, file).Replace('\\', '/')); Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target); } }
    }
    public string Relative(JsonObject plan) => plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy";
    public JsonObject Plan(string name) => DeploymentPlans.Create(new JsonObject { ["Provider"] = "Example", ["Instance"] = name, ["NodeName"] = name, ["Role"] = "RealityEntry", ["RealityTarget"] = "example.com", ["IPv4"] = "192.0.2.10", ["SshPort"] = 22, ["BandwidthMbps"] = 100 }, Versions, Paths, false);
    public void SaveInstance(JsonObject plan) { var directory = Paths.Instance(Relative(plan)); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); Store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), RealitySecrets()); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["CurrentManagementPort"] = plan.Number("Ports.SshPrimary"), ["Audit"] = new JsonObject { ["MemoryKiB"] = 1048576 } }); }
    public static JsonObject RealitySecrets() => new() { ["Xray"] = new JsonObject { ["Uuid"] = Guid.NewGuid().ToString(), ["RealityPrivateKey"] = ServerConfigurations.RandomKey(32), ["RealityClientKey"] = ServerConfigurations.RandomKey(32), ["ShortId"] = "abcd1234" }, ["AdminPassword"] = "synthetic-password" };
    public WorkflowEngine Engine(FakeRemote remote) => new(Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation());
    public void Dispose() { var full = Path.GetFullPath(Root); if (!full.Contains(Path.DirectorySeparatorChar + ".test-output" + Path.DirectorySeparatorChar, StringComparison.Ordinal)) throw new Exception("cleanup boundary"); SafePath.CheckTree(full); Directory.Delete(full, true); }
}
internal sealed class TestProtector : ISecretProtector { public string Format => "TEST-ONLY"; public byte[] Protect(ReadOnlySpan<byte> data) => data.ToArray().Select(b => (byte)(b ^ 0x73)).ToArray(); public byte[] Unprotect(ReadOnlySpan<byte> data) => Protect(data); }
internal sealed class NoopKeyAccess : IPrivateKeyAccess { public void PrepareManagedCopy(string path) { } }
internal sealed class FakeWorkflow(Func<CancellationToken, Task<TaskOutcome>> run) : IOperationWorkflow { public Task<TaskOutcome> ExecuteAsync(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellationToken) => run(cancellationToken); }
internal sealed class FakeUser(Func<string, string?>? secret = null, Func<UserDecision, bool>? confirm = null) : IUserInteraction
{
    public List<string> SecretPrompts { get; } = new();
    public List<UserDecision> Decisions { get; } = new();
    public Task<bool> ConfirmHostAsync(HostIdentity identity, CancellationToken cancellationToken) => Task.FromResult(true);
    public Task<bool> ConfirmAsync(UserDecision decision, CancellationToken cancellationToken) { Decisions.Add(decision); return Task.FromResult(confirm?.Invoke(decision) ?? true); }
    public Task<string?> SecretAsync(string title, CancellationToken cancellationToken) { SecretPrompts.Add(title); return Task.FromResult(secret == null ? "synthetic-password" : secret(title)); }
}
internal sealed class FakeKeys : IManagedKeyStore { public string Prepare(string directory, string source, string? passphrase = null) { Directory.CreateDirectory(directory); var file = SafePath.Resolve(directory, "id_vps_management"); File.WriteAllText(file, "fixture"); File.WriteAllText(file + ".pub", "fixture-public"); return file; } }
internal sealed class FakeValidation : IProtocolValidation { public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string privateDirectory, IUserInteraction user, IProgress<string> progress, CancellationToken cancellationToken) => Task.FromResult(new JsonObject { ["Status"] = "Passed" }); public void Export(JsonObject plan, JsonObject secrets, string directory) => ClientProfiles.Export(plan, secrets, directory); }
internal sealed class FakeTools : IExternalToolRunner { public Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, string? input, TimeSpan timeout, CancellationToken cancellationToken) => Task.FromResult(new CommandResult(1, "", "synthetic-credential")); }
internal sealed class FakeAssets : IValidationAssets { public string ResolveCore(string name) => name; public string DataDirectory => "unused"; }
internal sealed class SelectedAssets(IValidationAssets inner, string allowed) : IValidationAssets { public string ResolveCore(string name) => name == allowed ? inner.ResolveCore(name) : throw new Exception("Unselected core resolved."); public string DataDirectory => inner.DataDirectory; public string ExpectedVersion(string name) => inner.ExpectedVersion(name); }
internal sealed class FakeRemote : IRemoteSessionFactory, IRemoteSession
{
    private readonly JsonObject protocolInventory = new();
    public void SeedProtocols(JsonObject plan)
    {
        HealthAudit["Timers"] = new JsonObject { ["CertbotRenewEnabled"] = true, ["CertbotRenewActive"] = true };
        HealthAudit["Ssh"] = new JsonObject { ["Valid"] = true, ["PubkeyAuthentication"] = "yes", ["Ports"] = new JsonArray(plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue")) };
        HealthAudit["Nftables"] = new JsonObject { ["Valid"] = true };
        foreach (var role in DeploymentPlans.Roles[..3])
        {
            var enabled = plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role));
            protocolInventory[role] = new JsonObject { ["Installed"] = ComponentInstallations.ProtocolInstalled(plan, role), ["Enabled"] = enabled, ["Active"] = enabled };
            HealthAudit.Put("Services." + role, HealthService(ComponentInstallations.ProtocolInstalled(plan, role), enabled, enabled));
        }
    }
    public string InstallationCheckCode { get; set; } = "";
    public string PostInstallationCheckCode { get; set; } = "";
    public Action<string>? ObserveAsset { get; set; }
    public const string Backup = "/root/vps-deploy-backups/20000101-000000/protocol-lifecycle";
    public List<string> Commands { get; } = new(); public int Mutations { get; private set; } public string FailAsset { get; set; } = ""; public string StatusTaskId { get; set; } = ""; public string StatusPhase { get; set; } = "None"; public string ArmedComponents { get; private set; } = "";
    public List<SshEndpoint> Endpoints { get; } = new();
    public string BaselineNetworkCapture { get; private set; } = "";
    public string BaselineNetworkRestore { get; private set; } = "";
    public string StatusBackup { get; set; } = Backup;
    public bool VerifyUnownedAllowed { get; set; } = true;
    public bool MonitoringPresent { get; set; } = true;
    public string RestoredControllerVersion { get; set; } = "1.0.0";
    public JsonObject ComponentRelease { get; set; } = new();
    public JsonObject HealthAudit { get; set; } = new() { ["SchemaVersion"] = 2, ["CollectedAt"] = DateTimeOffset.UtcNow, ["ChecksIncomplete"] = new JsonArray(), ["Certificates"] = new JsonObject { ["AnyTls"] = new JsonObject { ["Present"] = true, ["DaysRemaining"] = 90 } }, ["Services"] = new JsonObject { ["KomariAgent"] = HealthService(false), ["KomariController"] = HealthService(false), ["Cloudflared"] = HealthService(false) } };
    public JsonObject AgentConfiguration { get; set; } = new() { ["endpoint"] = "https://monitor.example.com", ["token"] = "synthetic-agent-token" };
    public JsonObject TunnelAccessAudit { get; set; } = new() { ["Passed"] = true, ["ConnectorReady"] = true, ["LocalVersion"] = "1.5.1", ["PublicVersion"] = "1.5.1", ["Code"] = "" };
    public JsonObject NetworkAudit { get; set; } = NetworkTestData.Observation();
    public Dictionary<string, byte[]> ProtocolConfigs { get; } = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> protocolConfigBackup = new(StringComparer.Ordinal);
    public Dictionary<string, byte[]> RestoreProtocolConfigs { get; } = new(StringComparer.Ordinal);
    public bool CorruptRouteOnUpgrade { get; set; }
    public bool LoseOutboundApplyAcknowledgement { get; set; }
    public bool LoseOutboundCommitAcknowledgement { get; set; }
    public bool HopProbeFailure { get; set; }
    public bool HopProbeIncomplete { get; set; }
    public static JsonObject HealthService(bool installed, bool enabled = false, bool active = false, bool supported = true) => new() { ["Installed"] = installed, ["Enabled"] = enabled, ["Active"] = active, ["SupportedLayout"] = supported, ["ProcessMatchesBinary"] = active ? JsonValue.Create(true) : null };
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction interaction, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); Endpoints.Add(endpoint); return Task.FromResult<IRemoteSession>(this); }
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken cancellationToken) => Task.FromResult(new CommandResult(0, ArchiveStore.Digest(Encoding.UTF8.GetBytes("fixture-archive")) + "  file", ""));
    public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken cancellationToken)
    {
        var asset = payload.Split('\n')[0].Replace("# MXH asset: ", ""); if (!asset.EndsWith(".sh")) return Task.FromResult(new CommandResult(0, "VPSDEPLOY_SSH_OK\n", "")); Commands.Add(asset); if (mutating) Mutations++;
        if (asset == "protocol-migration-arm-rollback.sh") { var match = System.Text.RegularExpressions.Regex.Match(payload, "export VPS_PARAM_COMPONENTS=.+?'([A-Za-z0-9+/=]+)' "); ArmedComponents = Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)); }
        if (asset == "deployment-baseline-arm.sh") BaselineNetworkCapture = Parameter("NETWORK_MANAGED");
        if (asset == "deployment-baseline-rollback.sh") BaselineNetworkRestore = Parameter("RESTORE_NETWORK");
        if (asset == FailAsset) throw new IOException("synthetic connection lost");
        ObserveAsset?.Invoke(asset);
        static string Marker(string name, string value) => "VPSDEPLOY_" + name + "_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value)) + "\n";
        string Parameter(string name)
        {
            var match = System.Text.RegularExpressions.Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' ");
            return match.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) : "";
        }
        if (ProtocolConfigs.Count > 0)
        {
            var protocol = Parameter("ROLE");
            if (asset is "server-outbound-read.sh" or "maintenance-protocol-config-read.sh")
            {
                var bytes = ProtocolConfigs[protocol];
                return Task.FromResult(new CommandResult(0, Marker("SERVER_CONFIG", Encoding.UTF8.GetString(bytes)) + Marker("SERVER_CONFIG_SHA256", ArchiveStore.Digest(bytes)) + (asset == "server-outbound-read.sh" ? "VPSDEPLOY_SERVER_OUTBOUND_READ\n" : ""), ""));
            }
            if (asset == "server-hop-probe.sh")
            {
                if (HopProbeFailure) return Task.FromResult(new CommandResult(1, "", "synthetic hop probe failed"));
                var requests = JsonNode.Parse(Parameter("PROBES_JSON"))!.AsArray();
                var items = new JsonArray(requests.OfType<JsonObject>().Select(r => (JsonNode?)new JsonObject { ["Id"] = r.Text("Id"), ["Status"] = "Passed", ["Egress"] = r.Text("ExpectedAddress"), ["From"] = "EntryServer", ["Network"] = "TCP" }).ToArray());
                if (HopProbeIncomplete && items.Count > 0) items.RemoveAt(0);
                return Task.FromResult(new CommandResult(0, Marker("HOP_VALIDATION", new JsonObject { ["Status"] = "Passed", ["Items"] = items }.ToJsonString()) + "VPSDEPLOY_SERVER_HOPS_PASSED\n", ""));
            }
            if (asset == "protocol-migration-arm-rollback.sh")
            {
                protocolConfigBackup.Clear();
                foreach (var item in ProtocolConfigs.Where(item => ArmedComponents.Split(',').Contains(item.Key) || ArmedComponents.Split(',').Contains("Protocols"))) protocolConfigBackup[item.Key] = item.Value.ToArray();
                StatusTaskId = Parameter("CONTROL_TASK_ID"); StatusPhase = "Armed";
            }
            if (asset is "server-outbound-apply.sh" or "maintenance-protocol-config-apply.sh")
            {
                if (ArchiveStore.Digest(ProtocolConfigs[protocol]) != Parameter("EXPECTED_CONFIG_SHA256")) return Task.FromResult(new CommandResult(1, "", "configuration changed"));
                ProtocolConfigs[protocol] = Encoding.UTF8.GetBytes(Parameter("CONFIG_JSON"));
                if (asset == "server-outbound-apply.sh" && LoseOutboundApplyAcknowledgement) throw new IOException("synthetic lost outbound acknowledgement");
                return Task.FromResult(new CommandResult(0, asset == "server-outbound-apply.sh" ? "VPSDEPLOY_SERVER_OUTBOUND_APPLIED\n" : "VPSDEPLOY_CREDENTIAL_CONFIG_APPLIED\n", ""));
            }
            if (asset == "proxy-core-upgrade.sh" && CorruptRouteOnUpgrade)
            {
                var config = JsonNode.Parse(ProtocolConfigs[protocol])!.AsObject(); config["outbounds"]!.AsArray().RemoveAt(config["outbounds"]!.AsArray().Count - 1); ProtocolConfigs[protocol] = Encoding.UTF8.GetBytes(config.ToJsonString());
            }
            if (asset == "maintenance-restore-apply.sh") foreach (var item in RestoreProtocolConfigs) ProtocolConfigs[item.Key] = item.Value.ToArray();
            if (asset == "protocol-migration-trigger-rollback.sh") { foreach (var item in protocolConfigBackup) ProtocolConfigs[item.Key] = item.Value.ToArray(); StatusPhase = "RolledBack"; }
            if (asset == "maintenance-transaction-commit.sh") { StatusPhase = "Committed"; if (LoseOutboundCommitAcknowledgement) throw new IOException("synthetic lost commit acknowledgement"); }
        }
        if (asset == "maintenance-komari.sh") return Task.FromResult(new CommandResult(0, Parameter("ACTION") == "Status" ? string.Join('\n', new[] { "komari-agent.service", "komari.service", "cloudflared.service" }.Select(service => service + "=" + (MonitoringPresent ? "true,true,true" : "false,false,false"))) : "VPSDEPLOY_KOMARI_LIFECYCLE_OK\n" + (Parameter("ACTION") == "ControllerRestore" ? Marker("KOMARI_RESTORED_VERSION", RestoredControllerVersion) + Marker("KOMARI_RESTORED_SHA256", new string('b', 64)) : Parameter("ACTION") == "ControllerBackup" ? Marker("KOMARI_BACKUP", "/root/komari-controller-20000101-000000.tar.gz") : ""), ""));
        if (asset == "firewall-preflight.sh") return Task.FromResult(new CommandResult(0, "VPSDEPLOY_FIREWALL_SCOPE_OK\n", ""));
        if (asset == "component-release-latest.sh") return Task.FromResult(new CommandResult(0, Marker("COMPONENT_RELEASE", ComponentRelease.ToJsonString()), ""));
        if (asset == "proxy-core-upgrade.sh") return Task.FromResult(new CommandResult(0, "VPSDEPLOY_PROXY_CORE_UPDATED\n", ""));
        if (asset == "maintenance-health-audit.sh")
        {
            foreach (var item in protocolInventory) if (item.Value != null) HealthAudit.Put("Services." + item.Key, HealthService(item.Value.Flag("Installed"), item.Value.Flag("Enabled"), item.Value.Flag("Active")));
            return Task.FromResult(new CommandResult(0, Marker("HEALTH_AUDIT", HealthAudit.ToJsonString()), ""));
        }
        if (asset == "tunnel-public-audit.sh") return Task.FromResult(new CommandResult(0, Marker("TUNNEL_ACCESS", TunnelAccessAudit.ToJsonString()) + "VPSDEPLOY_TUNNEL_ACCESS_OK\n", ""));
        if (asset == "network-audit.sh") return Task.FromResult(new CommandResult(0, Marker("NETWORK_AUDIT", NetworkAudit.ToJsonString()), ""));
        if (asset == "network-preflight.sh") return Task.FromResult(new CommandResult(0, "VPSDEPLOY_NETWORK_PREFLIGHT_OK\n", ""));
        if (asset == "network-apply.sh")
        {
            NetworkAudit["Sysctl"]!["net.core.default_qdisc"] = "fq";
            NetworkAudit["Sysctl"]!["net.ipv4.tcp_congestion_control"] = "bbr";
            return Task.FromResult(new CommandResult(0, "VPSDEPLOY_NETWORK_APPLIED\n", ""));
        }
        if (asset == "component-install-preflight.sh")
        {
            var code = Parameter("VERIFY_ONLY") == "true" ? PostInstallationCheckCode : InstallationCheckCode;
            return Task.FromResult(new CommandResult(0, Marker("INSTALLATION_CHECK", new JsonObject { ["Allowed"] = code == "", ["Code"] = code, ["Services"] = new JsonObject(), ["NftablesSha256"] = new string('a', 64) }.ToJsonString()), ""));
        }
        if (asset is "komari-agent.sh" or "monitoring-component-install.sh")
        {
            if (asset == "komari-agent.sh" && Parameter("NODE_NAME") == "") return Task.FromResult(new CommandResult(1, "", "VPS_PARAM_NODE_NAME: required parameter"));
            var name = asset == "komari-agent.sh" ? "KomariAgent" : Parameter("COMPONENT") == "Tunnel" ? "Cloudflared" : "KomariController";
            HealthAudit.Put("Services." + name, HealthService(true, true, true));
            if (name == "KomariAgent") AgentConfiguration = new JsonObject { ["endpoint"] = Parameter("ENDPOINT"), ["token"] = Parameter("TOKEN") };
        }
        foreach (var role in DeploymentPlans.Roles[..3]) protocolInventory[role] ??= new JsonObject { ["Installed"] = false, ["Enabled"] = false, ["Active"] = false };
        if (asset is "xray-apply-config.sh" or "anytls-apply-config.sh" or "sing-box-apply-config.sh")
        {
            var role = asset == "xray-apply-config.sh" ? "RealityEntry" : asset == "anytls-apply-config.sh" ? "AnyTlsEntry" : "ShadowsocksLanding";
            protocolInventory[role] = new JsonObject { ["Installed"] = true, ["Enabled"] = true, ["Active"] = true };
            if (role == "AnyTlsEntry" && Parameter("KEEP_OTHER_PROTOCOLS") != "true") { protocolInventory["RealityEntry"]!["Enabled"] = false; protocolInventory["RealityEntry"]!["Active"] = false; }
        }
        if (asset == "protocol-lifecycle-apply-state.sh") foreach (var (role, name) in new[] { ("RealityEntry", "REALITY_ENABLED"), ("AnyTlsEntry", "ANYTLS_ENABLED"), ("ShadowsocksLanding", "SHADOWSOCKS_ENABLED") }) { protocolInventory[role]!["Enabled"] = Parameter(name) == "true"; protocolInventory[role]!["Active"] = Parameter(name) == "true"; }
        if (asset == "protocol-lifecycle-uninstall.sh") protocolInventory[Parameter("REMOVE_ROLE")] = new JsonObject { ["Installed"] = false, ["Enabled"] = false, ["Active"] = false };
        if (asset == "maintenance-decommission.sh") foreach (var role in DeploymentPlans.Roles[..3]) { protocolInventory[role]!["Enabled"] = false; protocolInventory[role]!["Active"] = false; if (Parameter("SCOPE") == "RemoveManaged") protocolInventory[role]!["Installed"] = false; }
        var deploymentOutput = asset switch
        {
            "deployment-baseline-arm.sh" => "VPSDEPLOY_DEPLOYMENT_BASELINE_OK\n" + Marker("BASELINE_DIR", "/root/vps-deploy-transaction-baselines/" + Parameter("TRANSACTION_ID")),
            "deployment-baseline-status.sh" => Marker("DEPLOYMENT_BASELINE_STATUS", "Ready"),
            "deployment-baseline-rollback.sh" => "VPSDEPLOY_DEPLOYMENT_ROLLBACK_OK\n",
            "base-system.sh" => "VPSDEPLOY_BASE_OK\n", "target-audit.sh" => Marker("TARGET_JSON", "{\"automatic_pass\":true}"),
            "xray-generate-credentials.sh" => Marker("XRAY_SECRET", Fixture.RealitySecrets()["Xray"]!.ToJsonString()),
            "anytls-generate-ech.sh" => Marker("ECH_KEYS", "synthetic-ech-key") + Marker("ECH_CONFIG", "synthetic-ech-config"),
            "certbot-dns-setup.sh" => "VPSDEPLOY_CERTBOT_DNS_OK\n", "local-https-target.sh" => "VPSDEPLOY_LOCAL_HTTPS_OK\n",
            "component-firewall-add.sh" => "VPSDEPLOY_COMPONENT_FIREWALL_OK\n", "monitoring-component-install.sh" => "VPSDEPLOY_MONITORING_INSTALLED\n",
            "maintenance-decommission.sh" => "VPSDEPLOY_DECOMMISSION_OK\n",
            "maintenance-restore-apply.sh" => "VPSDEPLOY_MANUAL_RESTORE_APPLIED\n",
            "protocol-lifecycle-apply-state.sh" => "VPSDEPLOY_PROTOCOL_STATE_APPLIED\n",
            "protocol-lifecycle-status.sh" => "VPSDEPLOY_PROTOCOL_STATUS_OK\n" + Marker("PROTOCOL_INVENTORY", protocolInventory.ToJsonString()),
            "final-validate.sh" => "VPSDEPLOY_FINAL_OK\n" + Marker("TIME_SYNC", "yes"),
            "ssh-cutover.sh" => "VPSDEPLOY_CUTOVER_PENDING\n", "ssh-cutover-confirm.sh" => "VPSDEPLOY_CUTOVER_CONFIRMED\n",
            "deployment-snapshot-delete.sh" => "VPSDEPLOY_SNAPSHOT_DELETE_OK\n", _ => null
        };
        if (deploymentOutput != null) return Task.FromResult(new CommandResult(0, deploymentOutput, ""));
        if (asset == "maintenance-transaction-status.sh" && Parameter("ACTION") == "VerifyUnowned") return Task.FromResult(new CommandResult(VerifyUnownedAllowed ? 0 : 1, VerifyUnownedAllowed ? "VPSDEPLOY_UNOWNED_TRANSACTION_CLEAR\n" : "", ""));
        var output = asset switch { "audit.sh" => Marker("OS_ID", "debian") + Marker("OS_VERSION", "13") + Marker("ARCH", "x86_64") + Marker("MEMORY_KIB", "1048576") + Marker("EXISTING_SERVICES", "") + Marker("NFT_LINES", "0"), "maintenance-health-audit.sh" => Marker("HEALTH_AUDIT", "{\"SchemaVersion\":1}"), "protocol-migration-arm-rollback.sh" => Marker("BACKUP_DIR", Backup), "network-tuning.sh" => Marker("BACKUP_DIR", "/root/fixture-network"), "maintenance-transaction-commit.sh" => "VPSDEPLOY_MAINTENANCE_COMMITTED\n", "maintenance-transaction-status.sh" => Marker("TRANSACTION_BACKUP", StatusBackup) + Marker("TRANSACTION_PHASE", StatusPhase) + Marker("CONTROL_TASK_ID", StatusTaskId), "protocol-migration-trigger-rollback.sh" => "VPSDEPLOY_MIGRATION_ROLLBACK_OK\n", _ => "" }; return Task.FromResult(new CommandResult(0, output, ""));
    }
    public Task<byte[]> ReadFileAsync(string absolutePath, CancellationToken cancellationToken)
    {
        var role = absolutePath switch { "/usr/local/etc/xray/config.json" => "RealityEntry", "/etc/sing-box-anytls/config.json" => "AnyTlsEntry", "/etc/sing-box/config.json" => "ShadowsocksLanding", _ => "" };
        return Task.FromResult(ProtocolConfigs.TryGetValue(role, out var bytes) ? bytes.ToArray() : Encoding.UTF8.GetBytes(absolutePath == "/etc/komari-agent/config.json" ? AgentConfiguration.ToJsonString() : absolutePath.EndsWith("/network-state.json", StringComparison.Ordinal) ? "{\"Version\":2}" : absolutePath.EndsWith("/firewall-state.json", StringComparison.Ordinal) ? "{\"Version\":1}" : "{}"));
    }
    public Task DownloadAsync(string absolutePath, string destination, CancellationToken cancellationToken) { Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.WriteAllText(destination, "fixture-archive"); return Task.CompletedTask; }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
