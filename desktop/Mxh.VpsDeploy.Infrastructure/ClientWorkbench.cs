using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Infrastructure;

public sealed class ClientWorkbench(ArchiveStore store, IExternalToolRunner tools, IValidationAssets assets, string python)
{
    private string SchemeFile(JsonObject scheme)
    {
        var id = scheme.Text("Id"); if (!System.Text.RegularExpressions.Regex.IsMatch(id, "^[a-f0-9]{32}$")) throw new OperationException("方案标识无效。");
        return store.Paths.Resolve("private/client-schemes/" + id + ".dotnet.private.json");
    }
    public void Save(JsonObject scheme) { ClientSchemes.UpgradeLayout(scheme); store.WriteSecret(SchemeFile(scheme), scheme); }
    public void Delete(JsonObject scheme)
    {
        var file = SchemeFile(scheme);
        if (new CandidatePublisher(store.Paths).Pending().Any(p => ArchiveStore.ReadJson(p).Text("SchemeId") == scheme.Text("Id"))) throw new OperationException("此方案有未完成的导出事务，请先恢复。");
        var root = store.Paths.Resolve("private/client-candidates");
        if (Directory.Exists(root))
        {
            SafePath.CheckTree(root);
            foreach (var directory in Directory.EnumerateDirectories(root))
            {
                var owner = SafePath.Resolve(directory, "candidate-owner.json");
                if (File.Exists(owner) && ArchiveStore.ReadJson(owner).Text("SchemeId") == scheme.Text("Id")) Directory.Delete(directory, true);
            }
        }
        SafePath.CheckLinks(file); File.Delete(file);
        // Completed export journals and their rollback copies belong to history, not to the editor.
    }
    public IEnumerable<JsonObject> List()
    {
        var directory = store.Paths.Resolve("private/client-schemes"); if (!Directory.Exists(directory)) return [];
        SafePath.CheckTree(directory);
        return Directory.EnumerateFiles(directory, "*.dotnet.private.json").Select(file =>
        {
            var scheme = store.ReadSecret(file); if (ClientSchemes.UpgradeLayout(scheme)) Save(scheme); return scheme;
        }).ToArray();
    }
    public async Task<JsonArray> ReadSourcesAsync(string clash, string sing, CancellationToken cancellationToken)
    {
        var args = new List<string> { store.Paths.Resolve("scripts/inspect_client_sources.py") };
        foreach (var (format, file) in new[] { ("--clash", clash), ("--sing-box", sing) }.Where(p => p.Item2 != "")) { SafePath.CheckLinks(file); args.AddRange([format, file]); }
        if (args.Count == 1) throw new OperationException("请选择所需客户端的来源文件。");
        var result = await tools.RunAsync(python, args, null, TimeSpan.FromSeconds(30), cancellationToken);
        result.RequireSuccess("来源配置无法提取受支持节点。"); return JsonNode.Parse(result.Output)!.AsArray();
    }
    public async Task<JsonObject> BuildAsync(JsonObject scheme, CancellationToken cancellationToken)
    {
        ClientSchemes.UpgradeLayout(scheme);
        MigrateManagedSources(scheme);
        if (scheme.Text("SourceMode") == "ExistingAuthority" && scheme["AuthorityNodes"] == null)
        {
            var original = await ReadSourcesAsync(ClientSchemes.Formats(scheme).Contains("Clash") ? scheme.Text("Clash") : "", ClientSchemes.Formats(scheme).Contains("SingBox") ? scheme.Text("SingBox") : "", cancellationToken);
            scheme["AuthorityNodes"] = new JsonArray(original.Select(n => (JsonNode?)JsonValue.Create(n!.Text("name"))).ToArray());
            foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>()) if (scheme.Strings("AuthorityNodes").Contains(node.Text("name")) && node["AuthorityName"] == null) node["AuthorityName"] = node.Text("name");
        }
        var formats = ClientSchemes.Formats(scheme); var specification = ClientSchemes.Specification(scheme); var sources = new JsonObject();
        foreach (var format in formats) { var source = scheme.Text(format); if (source == "") throw new OperationException("所选客户端缺少来源文件。"); var fingerprint = ClientSchemes.SourceFingerprint(source); if (scheme["SourceFingerprints"] is JsonObject recorded && recorded.Text(format) != "" && recorded.Text(format) != fingerprint) throw new OperationException("来源在读取后发生变化，请重新读取。"); sources[source] = fingerprint; }
        if (scheme["Sources"] is JsonObject originalSources) foreach (var item in originalSources) { if (ClientSchemes.SourceFingerprint(item.Key) != item.Value!.ToString()) throw new OperationException("节点来源发生变化，请重新读取。"); sources[item.Key] = item.Value.DeepClone(); }
        var origins = new JsonArray(scheme["Nodes"]!.AsArray().Where(n => n!["ManagedOrigin"] != null).Select(n => n!["ManagedOrigin"]!.DeepClone()).ToArray());
        ManagedNodeSources.Verify(store, origins);
        var directory = store.Paths.Resolve("private/client-candidates/" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "candidate-owner.json"), new JsonObject { ["SchemeId"] = scheme.Text("Id") });
        var specFile = SafePath.Resolve(directory, "layout.private.json"); ArchiveStore.WriteJson(specFile, specification);
        var args = new List<string> { store.Paths.Resolve("scripts/build_client_authority.py"), "--spec", specFile, "--output", directory };
        foreach (var format in formats) args.AddRange([format == "Clash" ? "--clash" : "--sing-box", scheme.Text(format)]);
        var result = await tools.RunAsync(python, args, null, TimeSpan.FromSeconds(60), cancellationToken);
        result.RequireSuccess("候选生成失败，请检查节点、连接关系与分组。");
        var candidate = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["OutputClients"] = scheme.Text("OutputClients", "Both"), ["Sources"] = sources, ["SpecFingerprint"] = ArchiveStore.Fingerprint(specification), ["ValidationStatus"] = "Pending", ["Targets"] = new JsonObject() };
        candidate["ManagedSources"] = origins;
        foreach (var format in formats) { candidate[format] = SafePath.Resolve(directory, format == "Clash" ? "Clash_General.candidate.yaml" : "sing-box-general.candidate.json"); candidate[format + "Hash"] = ClientSchemes.SourceFingerprint(candidate.Text(format)); }
        VerifySources(candidate); scheme["Candidate"] = candidate; Save(scheme); return candidate;
    }
    private void VerifySources(JsonObject candidate)
    {
        foreach (var source in candidate["Sources"]!.AsObject()) if (ClientSchemes.SourceFingerprint(source.Key) != source.Value!.ToString()) throw new OperationException("来源已变化，请重新生成候选。");
        if (candidate["ManagedSources"] is JsonArray origins) ManagedNodeSources.Verify(store, origins);
    }
    private void VerifyCandidate(JsonObject scheme, JsonObject candidate)
    {
        if (candidate.Text("OutputClients", "Both") != scheme.Text("OutputClients", "Both") || candidate.Text("SpecFingerprint") != ArchiveStore.Fingerprint(ClientSchemes.Specification(scheme))) throw new OperationException("方案已变化，请重新生成候选。");
        foreach (var format in ClientSchemes.Formats(scheme)) if (ClientSchemes.SourceFingerprint(candidate.Text(format)) != candidate.Text(format + "Hash")) throw new OperationException("候选已被外部修改。");
        if (candidate["Sources"] != null) VerifySources(candidate);
    }
    public async Task ValidateAsync(JsonObject scheme, CancellationToken cancellationToken)
    {
        var candidate = scheme["Candidate"]?.AsObject() ?? throw new OperationException("请先生成候选。");
        candidate["ValidationStatus"] = "Pending"; candidate.Remove("ValidationError"); candidate["Targets"] = new JsonObject(); Save(scheme);
        try
        {
            VerifyCandidate(scheme, candidate);
            foreach (var format in ClientSchemes.Formats(scheme))
            {
                var core = format == "Clash" ? "mihomo" : "sing-box"; var executable = assets.ResolveCore(core);
                await ProtocolValidation.VerifyVersion(assets, tools, core, executable, cancellationToken);
                if (format == "Clash")
                {
                    var data = SafePath.Resolve(Path.GetDirectoryName(candidate.Text(format))!, "validation-data-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(data);
                    try
                    {
                        if (Directory.Exists(assets.DataDirectory)) foreach (var file in Directory.EnumerateFiles(assets.DataDirectory)) { SafePath.CheckLinks(file); File.Copy(file, SafePath.Resolve(data, Path.GetFileName(file))); }
                        (await tools.RunAsync(executable, ["-t", "-d", data, "-f", candidate.Text(format)], null, TimeSpan.FromSeconds(40), cancellationToken)).RequireSuccess("Mihomo 校验失败。");
                    }
                    finally { SafePath.CheckTree(data); Directory.Delete(data, true); }
                }
                else (await tools.RunAsync(executable, ["check", "-c", candidate.Text(format)], null, TimeSpan.FromSeconds(40), cancellationToken)).RequireSuccess("sing-box 核心校验失败。");
            }
            VerifyCandidate(scheme, candidate); candidate["ValidationStatus"] = "Passed"; Save(scheme);
        }
        catch (Exception error)
        {
            candidate["ValidationStatus"] = error is OperationCanceledException ? "Pending" : "Failed";
            candidate["ValidationError"] = error is OperationCanceledException ? "校验已取消，请重新校验。" : SafeFailures.Describe(error).Message;
            Save(scheme); throw;
        }
    }
    public void PreparePublish(JsonObject scheme, string clash, string sing)
    {
        var candidate = scheme["Candidate"]?.AsObject() ?? throw new OperationException("请先生成候选。"); VerifyCandidate(scheme, candidate);
        if (candidate.Text("ValidationStatus") != "Passed") throw new OperationException("请先校验候选配置。");
        var targets = new JsonObject(); var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var selected in ClientSchemes.SelectedTargets(scheme, clash, sing)) { ClientSchemes.ValidatePublishPath(store.Paths, selected.Path); var path = Path.GetFullPath(selected.Path); if (!seen.Add(path)) throw new OperationException("配置文件不能使用同一路径。"); targets[path] = ClientSchemes.SourceFingerprint(path); }
        candidate["Targets"] = targets; Save(scheme);
    }
    public void Publish(JsonObject scheme, string clash, string sing)
    {
        var candidate = scheme["Candidate"]?.AsObject() ?? throw new OperationException("请先生成候选。"); VerifyCandidate(scheme, candidate);
        new CandidatePublisher(store.Paths, verifyManagedSources: VerifySources).Publish(candidate, clash, sing);
    }
    private void MigrateManagedSources(JsonObject scheme)
    {
        if (scheme["Sources"] is not JsonObject sources) return;
        var resolvedFiles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var instance in store.ListInstances())
        {
            var directory = store.Paths.Instance(instance.RelativePath);
            var files = new[] { "deployment-plan.json", "secrets.dotnet.private.json" }.Select(n => SafePath.Resolve(directory, n)).ToArray();
            if (!files.Any(sources.ContainsKey)) continue;
            var secrets = store.ReadSecret(files[1]);
            try
            {
                foreach (var pair in ClientProfiles.Nodes(instance.Plan, secrets))
                {
                    bool SameConnection(JsonObject node) => node["clash"] is JsonObject clash && node["sing_box"] is JsonObject sing && ManagedNodeSources.Fingerprint(pair with { Clash = clash, SingBox = sing }) == ManagedNodeSources.Fingerprint(pair);
                    foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n["ManagedOrigin"] == null && (n.Text("name") == pair.Name || SameConnection(n))).ToArray())
                    {
                        if (!SameConnection(node)) throw new OperationException("旧方案的受管节点已变化，请重新选择此节点更新来源。");
                        node["ManagedOrigin"] = ManagedNodeSources.Origin(instance.RelativePath, pair);
                    }
                }
                foreach (var file in files.Where(sources.ContainsKey)) resolvedFiles.Add(file);
            }
            finally { secrets.Clear(); }
        }
        // Decide after visiting every instance. A multi-instance scheme must
        // migrate in one pass; ambiguous rows retain their old source checks.
        if (scheme["Nodes"]!.AsArray().OfType<JsonObject>().All(n => n["ManagedOrigin"] != null)) foreach (var file in resolvedFiles) sources.Remove(file);
    }
}
