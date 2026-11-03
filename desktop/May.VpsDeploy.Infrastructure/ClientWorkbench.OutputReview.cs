using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record ClientPublishTargetReview(string Format, string Path, string BeforeHash, string AfterHash, string Summary);
public sealed record ClientPublishReview(string SchemeFingerprint, IReadOnlyList<ClientPublishTargetReview> Targets);

public sealed partial class ClientWorkbench
{
    private static string ReviewFileHash(string path)
    {
        SafePath.CheckLinks(path); if (!File.Exists(path)) return "missing";
        const int limit = 16 * 1024 * 1024;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > limit) throw new OperationException("差异审阅文件超过 16 MiB，请核对目标配置。");
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var buffer = new byte[65536]; var total = 0; int count;
        while ((count = stream.Read(buffer)) != 0) { total += count; if (total > limit) throw new OperationException("差异审阅文件在读取期间变大，请重新核对。"); hash.AppendData(buffer, 0, count); }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
    public async Task<ClientPublishReview> PreviewPublishAsync(JsonObject scheme, string clash, string sing, CancellationToken token)
    {
        var fingerprint = ArchiveStore.Fingerprint(scheme);
        var candidate = scheme["Candidate"]?.AsObject() ?? throw new OperationException("请先生成候选。"); VerifyCandidate(scheme, candidate);
        if (candidate.Text("ValidationStatus") != "Passed") throw new OperationException("请先校验候选配置。");
        var targets = ClientSchemes.SelectedTargets(scheme, clash, sing).Select(t => (t.Format, Path: Path.GetFullPath(t.Path))).ToArray();
        if (targets.Select(t => t.Path).Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal).Count() != targets.Length) throw new OperationException("配置文件不能使用同一路径。");
        var review = new List<ClientPublishTargetReview>();
        foreach (var target in targets)
        {
            ClientSchemes.ValidatePublishPath(store.Paths, target.Path);
            if (Directory.Exists(target.Path)) throw new OperationException("导出目标应为文件。");
            var before = ReviewFileHash(target.Path); var after = candidate.Text(target.Format + "Hash");
            var result = await tools.RunAsync(python, [store.Paths.Resolve("scripts/client_output_review.py"), "review", "--format", target.Format, "--before", target.Path, "--after", candidate.Text(target.Format)], null, TimeSpan.FromSeconds(20), token);
            result.RequireSuccess("目标或候选配置无法安全解析；未写入文件。请检查格式，或选择新的输出文件。");
            var details = JsonNode.Parse(result.Output)!.AsObject();
            if (details.Text("BeforeHash") != before || details.Text("AfterHash") != after || ReviewFileHash(target.Path) != before) throw new OperationException("差异审阅期间文件已变化，请重试。");
            string Delta(string label, string key) => label + "：新增 " + details.Number(key + ".Added") + "，移除 " + details.Number(key + ".Removed") + "，修改 " + details.Number(key + ".Changed");
            string Changed(string label, string key) => label + "：" + (details.Flag(key) ? "有变化" : "保留");
            var summary = before == after ? "文件内容相同，无需替换。" : string.Join("\n", new[] { before == "missing" ? "新建文件" : "替换已有文件（保留恢复副本）", Delta("节点／出站", "Nodes"), Delta("代理组", "Groups"), Changed("分流规则", "RulesChanged"), Changed("DNS", "DnsChanged"), Changed("监听／入站", "ListenersChanged"), Changed("其他设置", "SettingsChanged") });
            review.Add(new(target.Format, target.Path, before, after, summary));
        }
        token.ThrowIfCancellationRequested(); VerifyCandidate(scheme, candidate);
        if (ArchiveStore.Fingerprint(scheme) != fingerprint) throw new OperationException("方案已变化，请重新审阅。");
        foreach (var target in review) if (ReviewFileHash(target.Path) != target.BeforeHash) throw new OperationException("目标已变化，请重新审阅。");
        // No candidate metadata or journal is written until explicit confirmation.
        return new(fingerprint, review.AsReadOnly());
    }

    public void PublishReviewed(JsonObject scheme, ClientPublishReview review)
    {
        if (ArchiveStore.Fingerprint(scheme) != review.SchemeFingerprint) throw new OperationException("方案或候选已变化，请重新审阅导出。");
        var candidate = scheme["Candidate"]?.DeepClone().AsObject() ?? throw new OperationException("请先生成候选。"); VerifyCandidate(scheme, candidate);
        if (candidate.Text("ValidationStatus") != "Passed" || review.Targets.Count != ClientSchemes.Formats(scheme).Count() || !review.Targets.Select(t => t.Format).SequenceEqual(ClientSchemes.Formats(scheme))) throw new OperationException("审阅记录与所选客户端不一致。");
        var targets = new JsonObject();
        foreach (var target in review.Targets)
        {
            ClientSchemes.ValidatePublishPath(store.Paths, target.Path);
            if (target.AfterHash != candidate.Text(target.Format + "Hash") || ReviewFileHash(target.Path) != target.BeforeHash) throw new OperationException("候选或目标文件已变化，请重新审阅。");
            if (target.BeforeHash != target.AfterHash) targets[target.Path] = target.BeforeHash;
        }
        if (targets.Count == 0) return;
        // Keep the existing multi-file recovery transaction, including unchanged
        // peers, so a partial failure still restores the reviewed pair together.
        candidate["Targets"] = new JsonObject(review.Targets.Select(t => new KeyValuePair<string, JsonNode?>(t.Path, JsonValue.Create(t.BeforeHash))));
        new CandidatePublisher(store.Paths, verifyManagedSources: VerifySources).Publish(candidate,
            review.Targets.FirstOrDefault(t => t.Format == "Clash")?.Path ?? "",
            review.Targets.FirstOrDefault(t => t.Format == "SingBox")?.Path ?? "");
    }

    private void VerifyFragmentSources(JsonObject scheme, ClientFragmentPreview preview)
    {
        ClientSourceBarrier.RequireAvailable(store, "Scheme", scheme.Text("Id"));
        new ClientNodeGroupStore(store).Verify(scheme);
        var current = ClientNodeFragments.Preview(scheme, preview.Format, preview.SelectedIds);
        var ids = current.Rows.Select(r => r.Id).ToHashSet(StringComparer.Ordinal);
        var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => ids.Contains(n.Text("Id"))).ToArray();
        ManagedNodeSources.Verify(store, new JsonArray(nodes.Where(n => n["ManagedOrigin"] != null).Select(n => n["ManagedOrigin"]!.DeepClone()).ToArray()));
        ForwardedNodeSources.VerifyNodes(store, nodes);
        TcpChains.VerifyOrigins(store, new JsonArray(nodes.Where(n => n["TcpChainOrigin"] != null).Select(n => n["TcpChainOrigin"]!.DeepClone()).ToArray()));
        InboundSources.VerifyOrigins(store, new JsonArray(nodes.Where(n => n["InboundOrigin"] != null).Select(n => n["InboundOrigin"]!.DeepClone()).ToArray()));
        if (scheme["Sources"] is JsonObject files) foreach (var file in files) if (ClientSchemes.SourceFingerprint(file.Key) != file.Value!.ToString()) throw new OperationException("节点来源文件已变化，请重新读取。");
    }
    public async Task<string> GenerateFragmentAsync(JsonObject scheme, ClientFragmentPreview preview, CancellationToken token)
    {
        var document = ClientNodeFragments.Build(scheme, preview); VerifyFragmentSources(scheme, preview);
        var result = await tools.RunAsync(python, [store.Paths.Resolve("scripts/client_output_review.py"), "fragment", "--format", preview.Format], document.ToJsonString(), TimeSpan.FromSeconds(20), token);
        result.RequireSuccess("原生节点片段生成失败，未导出部分内容。");
        token.ThrowIfCancellationRequested(); ClientNodeFragments.Build(scheme, preview); VerifyFragmentSources(scheme, preview);
        if (Encoding.UTF8.GetByteCount(result.Output) > ClientNodeFragments.MaximumBytes) throw new OperationException("节点片段超过 1 MiB。");
        return result.Output;
    }
    public async Task SaveFragmentAsync(JsonObject scheme, ClientFragmentPreview preview, string target, CancellationToken token)
    {
        ClientSchemes.ValidatePublishPath(store.Paths, target); target = Path.GetFullPath(target);
        if (Path.GetExtension(target) != (preview.Format == "Clash" ? ".yaml" : ".json") || File.Exists(target) || Directory.Exists(target)) throw new OperationException("请选择新的原生片段文件，不覆盖已有文件。");
        var parent = Path.GetDirectoryName(target)!; SafePath.CheckLinks(parent); if (!Directory.Exists(parent)) throw new OperationException("请选择已存在的导出文件夹。");
        var content = await GenerateFragmentAsync(scheme, preview, token); var temporary = Path.Combine(parent, ".may-fragment-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { var bytes = new UTF8Encoding(false, true).GetBytes(content); try { stream.Write(bytes); stream.Flush(true); } finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); } }
            token.ThrowIfCancellationRequested(); ClientNodeFragments.Build(scheme, preview); VerifyFragmentSources(scheme, preview);
            ClientSchemes.ValidatePublishPath(store.Paths, target); File.Move(temporary, target, false);
        }
        finally { if (File.Exists(temporary)) { SafePath.CheckLinks(temporary); File.Delete(temporary); } }
    }
}
