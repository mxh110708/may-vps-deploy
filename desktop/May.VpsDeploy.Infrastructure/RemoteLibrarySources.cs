using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record RemoteLibraryReview(string SourceId, string Digest, string Fingerprint, JsonObject Document, string Summary);

// Fetching only stages encrypted, immutable data. Importing creates a library
// revision; applying that revision to a consumer remains a separate transaction.
public sealed class RemoteLibrarySources(ArchiveStore store, ClientTemplateStore templates, IClientSourceFetch fetch)
{
    private const string Root = "private/remote-library-sources/";
    private string FileName(string id) => store.Paths.Resolve(Root + ClientTemplates.Id(id) + ".private.json");
    public static void ValidateDefinition(JsonObject definition)
    {
        var uri = ClientSubscriptions.Validate(definition);
        if (uri.Scheme != "https" || definition.Text("Kind") is not ("Template" or "RuleSet") ||
            definition.Text("ExpectedSha256") != "" && !RouteDiagnostics.Digest(definition.Text("ExpectedSha256")))
            throw new OperationException("模板／规则来源须为 HTTPS；可填写固定 SHA-256，不接受脚本来源。");
    }
    public IReadOnlyList<JsonObject> List()
    {
        var root = store.Paths.Resolve(Root.TrimEnd('/')); if (!Directory.Exists(root)) return [];
        SafePath.CheckTree(root);
        var files = Directory.EnumerateFiles(root, "*.private.json").ToArray();
        if (files.Length > 32) throw new OperationException("远程模板／规则来源最多32项。");
        return files.Select(f => Read(Path.GetFileName(f).Split('.')[0])).ToArray();
    }
    public JsonObject Read(string id)
    {
        var file = FileName(id); SafePath.CheckLinks(file);
        if (new FileInfo(file).Length > 160 * 1024 * 1024) throw new OperationException("来源缓存超过大小限制。");
        var value = store.ReadSecret(file);
        if (value.Number("Schema") != 1 || value.Text("Id") != id || value["Definition"] is not JsonObject definition || definition.Text("Id") != id || value["Versions"] is not JsonArray versions || versions.Count > 32)
            throw new OperationException("来源缓存身份或版本无效。");
        ValidateDefinition(definition);
        var revisions = new HashSet<string>(); var digests = new HashSet<string>();
        foreach (var entry in versions.OfType<JsonObject>())
        {
            var document = Parse(definition.Text("Kind"), entry.Text("Content"));
            if (entry.Text("Digest") != ArchiveStore.Digest(Encoding.UTF8.GetBytes(entry.Text("Content"))) || entry.Text("Identity") != document.Text("Id") || entry.Text("Revision") != document.Text("Revision") || !revisions.Add(entry.Text("Revision")) || !digests.Add(entry.Text("Digest")))
                throw new OperationException("固定来源修订内容或摘要发生变化。");
        }
        if (versions.Any(v => v is not JsonObject)) throw new OperationException("来源修订格式无效。");
        return value;
    }
    public void Register(JsonObject definition)
    {
        ValidateDefinition(definition); var file = FileName(definition.Text("Id")); using var held = ClientSourceSync.LockFile(file);
        if (File.Exists(file)) throw new OperationException("来源身份已存在；不同地址请登记新来源。");
        if (List().Count >= 32) throw new OperationException("远程模板／规则来源最多32项。");
        store.WriteSecret(file, new() { ["Schema"] = 1, ["Id"] = definition.Text("Id"), ["Definition"] = definition.DeepClone(), ["LibraryId"] = Guid.NewGuid().ToString("N"), ["Versions"] = new JsonArray() });
    }
    public static JsonObject Parse(string kind, string content)
    {
        if (Encoding.UTF8.GetByteCount(content) > ClientSubscriptionDownload.MaximumBytes) throw new OperationException("模板／规则来源超过512 KiB。");
        try
        {
            var value = JsonNode.Parse(content, documentOptions: new() { MaxDepth = 48 })?.AsObject() ?? throw new OperationException("来源不是 JSON 对象。");
            if (kind == "RuleSet") return ServerRuleSets.Normalize(value);
            if (kind != "Template") throw new OperationException("未知来源类型。");
            ClientTemplates.Validate(value); return value;
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or ArgumentException) { throw new OperationException("来源格式无效，保留此前缓存和所有使用者。"); }
    }
    public async Task<string> FetchAsync(string id, CancellationToken token)
    {
        var original = Read(id); var stamp = ArchiveStore.Fingerprint(original); var definition = original["Definition"]!.AsObject();
        var content = await fetch.FetchAsync(definition, token); token.ThrowIfCancellationRequested();
        var document = Parse(definition.Text("Kind"), content); var digest = ArchiveStore.Digest(Encoding.UTF8.GetBytes(content));
        if (definition.Text("ExpectedSha256") != "" && definition.Text("ExpectedSha256") != digest) throw new OperationException("来源摘要与固定值不符，原版本保留。");
        // Inspect with the existing non-executing template renderer before cache acceptance.
        if (definition.Text("Kind") == "Template") { var check = document.DeepClone().AsObject(); templates.BindCurrentCores(check); await templates.InspectAsync(check, token); }
        using var held = ClientSourceSync.LockFile(FileName(id)); var current = Read(id);
        if (ArchiveStore.Fingerprint(current) != stamp) throw new OperationException("获取期间来源缓存已变化，请重新获取。");
        var versions = current["Versions"]!.AsArray();
        if (versions.Any(v => v!.Text("Identity") != document.Text("Id"))) throw new OperationException("远程来源更换了模板／规则身份，未接管新对象。");
        var same = versions.SingleOrDefault(v => v!.Text("Revision") == document.Text("Revision"));
        if (same != null) { if (same.Text("Digest") != digest) throw new OperationException("远程同一修订号返回不同内容，原缓存保留。"); return digest; }
        if (versions.Count >= 32) throw new OperationException("此来源已有32个固定修订，请另建来源，不自动清理旧版本。");
        token.ThrowIfCancellationRequested();
        versions.Add(new JsonObject { ["Digest"] = digest, ["Identity"] = document.Text("Id"), ["Revision"] = document.Text("Revision"), ["Content"] = content, ["FetchedAt"] = DateTimeOffset.UtcNow });
        if (Encoding.UTF8.GetByteCount(current.ToJsonString()) > 16 * 1024 * 1024) throw new OperationException("此来源缓存已达16 MiB序列化上限，保留旧修订；请登记新来源，不自动清理历史。");
        store.WriteSecret(FileName(id), current); return digest;
    }
    public RemoteLibraryReview Preview(string id, string digest)
    {
        var record = Read(id); var item = record["Versions"]!.AsArray().SingleOrDefault(v => v!.Text("Digest") == digest) ?? throw new OperationException("固定缓存版本已不存在。");
        var definition = record["Definition"]!.AsObject(); var document = Parse(definition.Text("Kind"), item.Text("Content"));
        var previous = new JsonObject();
        if (definition.Text("Kind") == "Template")
        {
            var versions = templates.List().Where(d => d.Text("Id") == record.Text("LibraryId")).ToArray();
            if (versions.Length > 0) previous = templates.Read(record.Text("LibraryId"), versions.Max(d => d.Number("Revision")));
            document["Id"] = record.Text("LibraryId"); document["Revision"] = previous.Count == 0 ? 1 : previous.Number("Revision") + 1;
            document["ParentFingerprint"] = previous.Count == 0 ? "" : ArchiveStore.Fingerprint(previous); templates.BindCurrentCores(document);
            if (previous.Count > 0) { var same = document.DeepClone().AsObject(); same["Revision"] = previous.Number("Revision"); same["ParentFingerprint"] = previous["ParentFingerprint"]!.DeepClone(); if (JsonNode.DeepEquals(previous, same)) document = previous.DeepClone().AsObject(); }
        }
        else
        {
            var rules = new ServerRuleSetStore(store); var old = rules.List().SingleOrDefault(r => r.Text("Id") == document.Text("Id"));
            if (old != null) previous = ServerRuleSetStore.Current(old);
            _ = rules.Preview(document);
        }
        var consumers = Consumers(definition.Text("Kind"), definition.Text("Kind") == "Template" ? record.Text("LibraryId") : document.Text("Id"));
        var changed = previous.Count == 0 ? document.Select(p => p.Key) : document.Where(p => !JsonNode.DeepEquals(p.Value, previous[p.Key])).Select(p => p.Key);
        var details = new List<string>();
        if (definition.Text("Kind") == "Template")
        {
            foreach (var parameter in document["Parameters"]!.AsObject().Where(p => !JsonNode.DeepEquals(p.Value, previous["Parameters"]?[p.Key])))
                details.Add(parameter.Key + "：" + (previous["Parameters"]?[parameter.Key]?.ToString() ?? "未设置") + " → " + parameter.Value);
            foreach (var basis in document["Bases"]!.AsObject())
                if (!JsonNode.DeepEquals(basis.Value, previous["Bases"]?[basis.Key])) details.Add((basis.Key == "Clash" ? "Mihomo" : "May Route") + " 基础 DNS／规则内容变化；新内容 SHA-256 " + ArchiveStore.Digest(Encoding.UTF8.GetBytes(basis.Value!.ToString())));
        }
        else
        {
            var delta = new ServerRuleSetStore(store).Preview(document).Changes;
            details.Add("匹配项：新增 " + delta.Count(d => d.Kind == "Added") + "，移除 " + delta.Count(d => d.Kind == "Removed"));
        }
        var summary = ClientSubscriptions.Label(definition) + "\n远程修订 " + item.Text("Revision") + "；SHA-256 " + digest + "\n变化字段：" + string.Join("、", changed) + "\n" + string.Join('\n', details) +
            "\n已有使用者 " + consumers.Count + " 项：\n" + string.Join('\n', consumers) + "\n确认只保存固定库修订。已有方案、入站及运行中的服务保留原修订；从各自入口另行预览、应用或恢复。可选旧缓存重新创建模板修订，规则库可选择历史版本。";
        var fingerprint = ArchiveStore.Fingerprint(new JsonObject { ["Record"] = record, ["Previous"] = previous, ["Document"] = document.DeepClone(), ["Consumers"] = new JsonArray(consumers.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()) });
        return new(id, digest, fingerprint, document, summary);
    }
    public async Task ImportAsync(RemoteLibraryReview review, CancellationToken token)
    {
        using var held = ClientSourceSync.LockFile(FileName(review.SourceId)); var current = Preview(review.SourceId, review.Digest);
        if (current.Fingerprint != review.Fingerprint || !JsonNode.DeepEquals(current.Document, review.Document)) throw new OperationException("来源、库版本或使用者在审阅后变化，请重新预览。");
        token.ThrowIfCancellationRequested();
        var record = Read(review.SourceId);
        if (record.Text("Definition.Kind") == "RuleSet") { var rules = new ServerRuleSetStore(store); rules.Apply(rules.Preview(current.Document)); }
        else
        {
            var same = templates.List().Any(d => d.Text("Id") == current.Document.Text("Id") && d.Number("Revision") == current.Document.Number("Revision") && d.Text("Fingerprint") == ArchiveStore.Fingerprint(current.Document));
            if (!same) await templates.SaveVersionAsync(current.Document, token);
        }
    }
    private IReadOnlyList<string> Consumers(string kind, string id)
    {
        var values = new List<string>();
        if (kind == "Template")
        {
            var root = store.Paths.Resolve("private/client-schemes"); if (!Directory.Exists(root)) return values; SafePath.CheckTree(root);
            foreach (var file in Directory.EnumerateFiles(root, "*.dotnet.private.json")) { var scheme = store.ReadSecret(file); try { if (scheme.Text("TemplateReference.Id") == id) values.Add("方案 " + scheme.Text("Id")[..8] + " · 修订 " + scheme.Text("TemplateReference.Revision")); } finally { scheme.Clear(); } }
        }
        else foreach (var instance in store.ListInstances()) { var count = CountReferences(instance.Plan, id); if (count > 0) values.Add("实例 " + ArchiveStore.Digest(Encoding.UTF8.GetBytes(instance.RelativePath))[..8] + " · " + count + " 处固定规则引用"); }
        return values.Order(StringComparer.Ordinal).ToArray();
    }
    private static int CountReferences(JsonNode? node, string id) => node is JsonObject o ? (o.Text("Kind") == "RuleSet" && o.Text("RuleSet.Id") == id ? 1 : o.Sum(p => CountReferences(p.Value, id))) : node is JsonArray a ? a.Sum(n => CountReferences(n, id)) : 0;
}
