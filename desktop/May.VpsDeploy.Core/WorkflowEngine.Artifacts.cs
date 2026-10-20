using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private static IEnumerable<string> CurrentArtifacts => new[] { "server-configs/xray-config.private.json", "server-configs/sing-box-anytls-config.private.json", "server-configs/sing-box-config.private.json" }.Concat(ClientProfiles.ExportNames.Select(n => "client-exports/" + n));
    private void SnapshotCurrentArtifacts(Context c, string backup, string[] components)
    {
        if (!components.Contains("Protocols") && !components.Any(DeploymentPlans.Roles[..3].Contains)) return;
        var original = new JsonObject();
        foreach (var relative in CurrentArtifacts)
        {
            var hash = ClientSchemes.SourceFingerprint(c.File(relative)); original[relative] = hash;
            var expected = (c.State["LocalArtifactHashes"] as JsonObject)?[relative]?.ToString();
            if (!string.IsNullOrEmpty(expected) && hash != expected) throw new OperationException("本地当前配置已被外部修改，请核对归档，未覆盖。");
            if (hash != "missing") ArchiveStore.AtomicWrite(SafePath.Resolve(backup, "artifacts/" + relative), File.ReadAllBytes(c.File(relative)));
        }
        c.Pending!["ArtifactOriginal"] = original; c.Pending["ArtifactExpected"] = original.DeepClone();
    }
    private void ExpectArtifact(Context c, string relative, string hash)
    {
        var previous = (c.Pending?["ArtifactExpected"] as JsonObject)?[relative]?.ToString() ?? (c.State["LocalArtifactHashes"] as JsonObject)?[relative]?.ToString();
        if (previous != null && ClientSchemes.SourceFingerprint(c.File(relative)) != previous) throw new OperationException("当前配置在操作中发生外部改动，未覆盖本地文件。");
        if (c.Pending?["ArtifactExpected"] is JsonObject expected) { expected[relative] = hash; c.Save(); }
        c.State["LocalArtifactHashes"] ??= new JsonObject(); c.State["LocalArtifactHashes"]![relative] = hash;
    }
    private void ExportProfiles(Context c)
    {
        var documents = ClientProfiles.Documents(c.Plan, c.Secrets).ToDictionary(d => d.Name, d => d.Document);
        foreach (var name in ClientProfiles.ExportNames) ExpectArtifact(c, "client-exports/" + name, documents.TryGetValue(name, out var document) ? ArchiveStore.Digest(ArchiveStore.JsonBytes(document)) : "missing");
        validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
        foreach (var name in ClientProfiles.ExportNames) c.State["LocalArtifactHashes"]!["client-exports/" + name] = ClientSchemes.SourceFingerprint(c.File("client-exports/" + name));
    }
    private void RestoreCurrentArtifacts(Context c)
    {
        if (c.Pending?["ArtifactOriginal"] is not JsonObject original || c.Pending["ArtifactExpected"] is not JsonObject expected) return;
        void Verify(KeyValuePair<string, JsonNode?> artifact)
        {
            if (!CurrentArtifacts.Contains(artifact.Key)) throw new OperationException("当前配置恢复记录超出受管范围。", true);
            var hash = ClientSchemes.SourceFingerprint(c.File(artifact.Key));
            if (hash != artifact.Value!.ToString() && hash != expected[artifact.Key]?.ToString()) throw new OperationException("当前配置含外部改动，未覆盖本地文件。", true);
            if (artifact.Value.ToString() != "missing" && ClientSchemes.SourceFingerprint(c.File(c.Pending.Text("LocalBackup") + "/artifacts/" + artifact.Key)) != artifact.Value.ToString()) throw new OperationException("当前配置恢复副本摘要不匹配。", true);
        }
        foreach (var artifact in original) Verify(artifact);
        foreach (var artifact in original)
        {
            Verify(artifact);
            var path = c.File(artifact.Key);
            if (artifact.Value!.ToString() == "missing") { if (File.Exists(path)) File.Delete(path); }
            else ArchiveStore.AtomicWrite(path, File.ReadAllBytes(c.File(c.Pending.Text("LocalBackup") + "/artifacts/" + artifact.Key)));
            c.State["LocalArtifactHashes"] ??= new JsonObject(); c.State["LocalArtifactHashes"]![artifact.Key] = artifact.Value.DeepClone();
        }
    }
    private void CleanupUninstalledProtocol(Context c, string role)
    {
        c.Secrets.Remove(role == "RealityEntry" ? "Xray" : role == "AnyTlsEntry" ? "AnyTls" : "Shadowsocks");
        if (c.State["ComponentUpgrades"] is JsonObject upgrades) upgrades.Remove(role);
        if (c.State["InstalledProgramVersions"] is JsonObject programs) programs.Remove(role);
        if (c.State["ServerConfigHashes"] is JsonObject hashes) hashes.Remove(role);
        c.State.Remove(role == "RealityEntry" ? "XrayVersion" : role == "AnyTlsEntry" ? "AnyTls" : "SingBoxVersion");
        var name = role == "RealityEntry" ? "xray-config.private.json" : role == "AnyTlsEntry" ? "sing-box-anytls-config.private.json" : "sing-box-config.private.json";
        var relative = "server-configs/" + name; var path = c.File(relative);
        if (File.Exists(path))
        {
            if (c.Pending?["ArtifactOriginal"] is JsonObject original && ClientSchemes.SourceFingerprint(path) != original[relative]?.ToString()) throw new OperationException("当前协议归档已被外部修改，未删除。");
            ExpectArtifact(c, relative, "missing"); File.Delete(path);
        }
    }
}
