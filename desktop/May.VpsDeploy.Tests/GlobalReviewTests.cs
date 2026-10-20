using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task GlobalReviewExperience()
    {
        using var f = new Fixture(repository);
        var token = f.Paths.Resolve("private/synthetic-dns.ini"); ArchiveStore.AtomicWrite(token, Encoding.UTF8.GetBytes("synthetic-dns-token"));
        var form = new JsonObject { ["Provider"] = "Example", ["Instance"] = "Local-HTTPS", ["IPv4"] = "192.0.2.10", ["RealityTarget"] = "entry.example.com", ["LocalTarget"] = true, ["ZoneName"] = "example.com", ["CertbotEmail"] = "qa@example.com", ["CloudflareTokenFile"] = token };
        var plan = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        Check(plan.Text("TrustedTls.RealityCertificateName") == "mxh-reality-target", "local Reality certificate is not recognized by the deploy hook");
        var collision = plan.DeepClone().AsObject(); collision.Put("Ports.XrayBackup", JsonValue.Create(collision.Number("Reality.LocalHttpsPort")));
        Refuses(() => DeploymentPlans.Validate(collision), "local TLS target may collide with a protocol listener");
        collision = plan.DeepClone().AsObject(); collision.Put("Ports.SshPrimary", JsonValue.Create(collision.Number("Reality.LocalHttpsPort")));
        Refuses(() => DeploymentPlans.Validate(collision), "local TLS target may collide with SSH");
        var agentPlan = f.Plan("Agent-url"); agentPlan.Put("Komari.Endpoint", JsonValue.Create("https://monitor.example.com/"));
        var secret = new JsonObject { ["KomariAgent"] = new JsonObject { ["Token"] = "synthetic-agent" } };
        Check(MonitoringArchives.SupplementAgent(agentPlan, secret, new() { ["endpoint"] = "https://monitor.example.com", ["token"] = "synthetic-agent" }), "trailing slash causes false Agent drift");
        Check(agentPlan.Text("Komari.Endpoint") == "https://monitor.example.com" && secret.Text("KomariAgent.Endpoint") == agentPlan.Text("Komari.Endpoint"), "Agent endpoint canonicalization did not update both archives");
        Check(!MonitoringArchives.SupplementAgent(agentPlan, secret, new() { ["endpoint"] = "https://other.example.com/", ["token"] = "synthetic-agent" }), "real Agent endpoint drift accepted");
        Refuses(() => MonitoringArchives.NormalizeEndpoint("https://user:synthetic@monitor.example.com"), "Agent endpoint with embedded credentials accepted");
        var remote = new FakeRemote(); remote.SeedProtocols(plan);
        remote.HealthAudit["CollectedAt"] = DateTimeOffset.UtcNow.ToString("O");
        remote.HealthAudit["Certificates"]!["Reality"] = new JsonObject { ["Present"] = true, ["DaysRemaining"] = 90 };
        var healthy = HealthReports.Build(plan, new(), remote.HealthAudit);
        Check(healthy.Text("Status") == "Passed", "complete local HTTPS health evidence rejected: " + healthy.ToJsonString());
        remote.HealthAudit["Certificates"]!["Reality"]!["DaysRemaining"] = 0;
        Check(HealthReports.Build(plan, new(), remote.HealthAudit).Text("Status") == "Warnings", "expired local Reality certificate appears healthy");
        remote.HealthAudit["Certificates"]!["Reality"]!["DaysRemaining"] = 90; remote.HealthAudit["Timers"]!["CertbotRenewActive"] = false;
        Check(HealthReports.Build(plan, new(), remote.HealthAudit).Text("Status") == "Warnings", "stopped certificate renewal appears healthy");
        foreach (var relative in new[] { "config/application.json", "runtime/python/python.exe", "private/desktop-settings.json", "private/client-candidates/output.json", "archive-location.private.json", "May-VPS-Deploy.exe" }) Refuses(() => ClientSchemes.ValidatePublishPath(f.Paths, f.Paths.Resolve(relative)), "export can overwrite application or private data: " + relative);
        ClientSchemes.ValidatePublishPath(f.Paths, f.Paths.Resolve("exports/independent.json")); Check(true, "independent output directory rejected");
        var diagnostics = "Cloudflare Zone API 拒绝 Token，请核对区域权限。";
        var safe = SafeFailures.Remote(new(21, "VPSDEPLOY_CERTBOT_SAFE_ERROR_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(diagnostics)) + "\n", "synthetic-hidden-diagnostic"), "certificate");
        Check(safe.Code == "CertificateProvisioningFailed" && safe.Message == diagnostics && !safe.Message.Contains("synthetic-hidden"), "explicit Certbot safe diagnostic lost or raw stderr exposed");
        var current = f.Plan("Config-only-uninstalled"); current.Put("ProtocolInventory.RealityEntry", new JsonObject { ["Installed"] = false, ["Enabled"] = false }); f.SaveInstance(current);
        var directory = f.Paths.Instance(f.Relative(current)); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); state.Put("DeploymentTransaction.Status", JsonValue.Create("Committed")); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
        var old = current.DeepClone().AsObject(); old.Put("ProtocolInventory.RealityEntry.Installed", JsonValue.Create(true));
        var relativeBackup = "maintenance-backups/" + new string('c', 32);
        f.Store.WriteSecret(SafePath.Resolve(directory, relativeBackup + "/secrets.dotnet.private.json"), Fixture.RealitySecrets());
        File.WriteAllText(SafePath.Resolve(directory, relativeBackup + "/remote-files.tar.gz"), "fixture-archive");
        ArchiveStore.WriteJson(SafePath.Resolve(directory, relativeBackup + "/restore-metadata.json"), new JsonObject { ["RemoteBackup"] = FakeRemote.Backup, ["BackupSha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes("fixture-archive")), ["Components"] = new JsonArray("Protocols"), ["SshPorts"] = current.Text("Ports.SshPrimary") + "," + current.Text("Ports.SshRescue"), ["OldPlan"] = old, ["OldState"] = new JsonObject(), ["SecretsRelativePath"] = relativeBackup + "/secrets.dotnet.private.json" });
        remote = new FakeRemote(); remote.SeedProtocols(current);
        await RefusesAsync(() => f.Engine(remote).ExecuteAsync(new(OperationKind.Restore, f.Relative(current), new() { ["Scope"] = "Protocol", ["RestoreMode"] = "ConfigOnly", ["Backup"] = FakeRemote.Backup }), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "config-only restore accepts an uninstalled program");
        Check(remote.Mutations == 0, "incompatible config-only restore started a remote snapshot or write");
    }
}
