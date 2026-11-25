using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record ClientTemplateReview(string SchemeId, string TemplateId, int Revision, string Fingerprint, JsonObject After, string Summary);
public sealed record ClientTemplateRestoreReview(string ApplicationId, string Fingerprint, string Summary);

public sealed class ClientTemplateStore(ArchiveStore store, IExternalToolRunner tools, IValidationAssets assets, string python)
{
    private const string Root = "private/client-templates/";
    private string VersionFile(string id, int revision) => store.Paths.Resolve(Root + "versions/" + ClientTemplates.Id(id) + "-" + ClientTemplates.Revision(revision) + ".private.json");
    private string SchemeFile(string id) => ServerOutboundRouting.SchemeFile(store.Paths, ClientTemplates.Id(id));
    private string JournalFile(string id) => store.Paths.Resolve(Root + "applications/" + ClientTemplates.Id(id) + ".private.json");
    private JsonObject CoreIdentities(string clients = "Both") => new(ClientTemplates.Cores(clients).Select(core => KeyValuePair.Create<string, JsonNode?>(core, new JsonObject { ["Version"] = assets.ExpectedVersion(core), ["Identity"] = assets.DiagnosticIdentity(core) })));
    public void BindCurrentCores(JsonObject document) => document["Cores"] = CoreIdentities(document.Text("Clients"));
    private void RequireArtifacts(JsonObject document) { foreach (var core in ClientTemplates.Cores(document.Text("Clients"))) _ = assets.ResolveCore(core); }
    public JsonObject BuiltIn()
    {
        var catalog = ArchiveStore.ReadJson(store.Paths.Resolve("config/client-templates.json"));
        var value = new JsonObject { ["Schema"] = 1, ["Id"] = catalog.Text("Id"), ["Revision"] = catalog.Number("Revision"), ["Name"] = catalog.Text("Name"), ["ParentFingerprint"] = "", ["Clients"] = catalog.Text("Clients"),
            ["Parameters"] = ClientTemplates.DefaultParameters(), ["Layout"] = ArchiveStore.ReadJson(store.Paths.Resolve("config/client-layout.default.json")),
            ["Bases"] = new JsonObject { ["Clash"] = File.ReadAllText(store.Paths.Resolve("templates/client/clash-general.template.yaml")), ["SingBox"] = File.ReadAllText(store.Paths.Resolve("templates/client/sing-box-general.template.json")) }, ["Cores"] = CoreIdentities() };
        ClientTemplates.Validate(value); return value;
    }
    public IReadOnlyList<JsonObject> List()
    {
        var result = new List<JsonObject>(); var path = store.Paths.Resolve(Root + "versions");
        if (Directory.Exists(path))
        {
            SafePath.CheckTree(path); var files = Directory.EnumerateFiles(path, "*.private.json").ToArray();
            if (files.Length > ClientTemplates.MaximumTemplates * ClientTemplates.MaximumVersions) throw new OperationException("模板库超过数量限制。");
            foreach (var file in files)
            {
                var record = ReadRecord(file); var doc = record["Document"]!.AsObject();
                if (file != VersionFile(doc.Text("Id"), doc.Number("Revision"))) throw new OperationException("模板文件归属不符。"); result.Add(Summary(doc)); record.Clear();
            }
        }
        var built = BuiltIn(); var duplicate = result.SingleOrDefault(d => d.Text("Id") == built.Text("Id") && d.Number("Revision") == built.Number("Revision"));
        if (duplicate == null) result.Add(Summary(built));
        else if (duplicate.Text("Fingerprint") != ArchiveStore.Fingerprint(built)) throw new OperationException("内置模板同修订号内容发生变化，需要维护者更新目录修订号；保留已固定版本。");
        return result.OrderBy(d => d.Text("Name"), StringComparer.Ordinal).ThenByDescending(d => d.Number("Revision")).ToArray();
    }
    private static JsonObject Summary(JsonObject document) => new() { ["Id"] = document.Text("Id"), ["Revision"] = document.Number("Revision"), ["Name"] = document.Text("Name"), ["Clients"] = document.Text("Clients"), ["Fingerprint"] = ArchiveStore.Fingerprint(document) };
    public JsonObject Read(string id, int revision)
    {
        var file = VersionFile(id, revision);
        if (File.Exists(file)) return ReadRecord(file)["Document"]!.DeepClone().AsObject();
        var builtin = BuiltIn(); if (id == builtin.Text("Id") && revision == builtin.Number("Revision")) return builtin;
        throw new OperationException("模板版本已不存在。");
    }
    private JsonObject ReadRecord(string file)
    {
        SafePath.CheckLinks(file); if (new FileInfo(file).Length > 3 * 1024 * 1024) throw new OperationException("模板版本超过大小限制。");
        var record = store.ReadSecret(file); var document = record["Document"] as JsonObject ?? throw new OperationException("模板快照格式无效。");
        ClientTemplates.Validate(document);
        if (!Path.GetFullPath(file).Equals(VersionFile(document.Text("Id"), document.Number("Revision")), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) throw new OperationException("模板文件与版本身份不符。");
        if (record.Number("Schema") != 1 || record.Text("Fingerprint") != ArchiveStore.Fingerprint(document) || record["Hashes"] is not JsonObject hashes || hashes.Count != document["Bases"]!.AsObject().Count || hashes.Any(p => !RouteDiagnostics.Digest(p.Value?.ToString() ?? ""))) throw new OperationException("模板快照摘要无效。");
        return record;
    }
    public JsonObject Draft(JsonObject source, bool newTemplate)
    {
        var copy = source.DeepClone().AsObject();
        copy["ParentFingerprint"] = newTemplate ? "" : ArchiveStore.Fingerprint(source);
        copy["Id"] = newTemplate ? Guid.NewGuid().ToString("N") : source.Text("Id");
        copy["Revision"] = newTemplate ? 1 : source.Number("Revision") + 1;
        if (newTemplate) copy["Name"] = source.Text("Name") + " · 自定义";
        BindCurrentCores(copy);
        return copy;
    }
    private async Task<JsonObject> Render(JsonObject document, CancellationToken token)
    {
        ClientTemplates.Validate(document);
        var result = await tools.RunAsync(python, [store.Paths.Resolve("scripts/client-template-library.py")], document.ToJsonString(), TimeSpan.FromSeconds(20), token);
        result.RequireSuccess("模板解析或依赖检查失败；请核对分组、HTTPS规则来源、未提供的本地文件和固定节点。未保存版本。");
        if (Encoding.UTF8.GetByteCount(result.Output) > 2 * 1024 * 1024) throw new OperationException("模板渲染返回超过大小限制。");
        var rendered = JsonNode.Parse(result.Output)?.AsObject() ?? throw new OperationException("模板渲染结果无效。");
        foreach (var format in ClientSchemes.Formats(new JsonObject { ["OutputClients"] = document.Text("Clients") }))
            if (rendered.Text("Hashes." + format) != ArchiveStore.Digest(Encoding.UTF8.GetBytes(rendered.Text("Contents." + format)))) throw new OperationException("模板渲染内容与摘要不符。");
        if (rendered["Dependencies"] is not JsonArray deps || deps.Count > 256) throw new OperationException("模板依赖数量无效。");
        return rendered;
    }
    public async Task<JsonObject> InspectAsync(JsonObject document, CancellationToken token)
    {
        var proof = await Render(document, token); RequireArtifacts(document);
        var deps = proof["Dependencies"]!.DeepClone().AsArray();
        foreach (var core in ClientTemplates.Cores(document.Text("Clients"))) deps.Add(new JsonObject { ["Format"] = core, ["Kind"] = "固定核心归档", ["Locator"] = assets.ExpectedVersion(core), ["Status"] = "PinnedArtifactAvailable" });
        return new() { ["Dependencies"] = deps };
    }
    public async Task SaveVersionAsync(JsonObject document, CancellationToken token)
    {
        var snapshot = document.DeepClone().AsObject(); var fingerprint = ArchiveStore.Fingerprint(snapshot); var rendered = await Render(snapshot, token);
        if (!JsonNode.DeepEquals(snapshot["Cores"], CoreIdentities(snapshot.Text("Clients")))) throw new OperationException("新修订须绑定当前配套核心；请重新从模板库创建修订。");
        RequireArtifacts(snapshot);
        var builtin = BuiltIn();
        if (snapshot.Number("Revision") == builtin.Number("Revision") + 1 && snapshot.Text("ParentFingerprint") != "" && !File.Exists(VersionFile(snapshot.Text("Id"), builtin.Number("Revision"))))
        {
            var parent = BuiltIn();
            if (parent.Text("Id") == snapshot.Text("Id") && ArchiveStore.Fingerprint(parent) == snapshot.Text("ParentFingerprint")) await SaveVersionAsync(parent, token);
        }
        using var held = ClientSourceSync.LockFile(store.Paths.Resolve(Root + "library"));
        var all = List(); var id = snapshot.Text("Id"); var revision = snapshot.Number("Revision"); var file = VersionFile(id, revision);
        if (File.Exists(file)) throw new OperationException("模板版本不可覆盖，请创建新修订。");
        var versionRoot = store.Paths.Resolve(Root + "versions");
        if (Directory.Exists(versionRoot) && Directory.EnumerateFiles(versionRoot, "*.private.json").Count() >= ClientTemplates.MaximumTemplates * ClientTemplates.MaximumVersions) throw new OperationException("模板库已达存储版本上限，保留现有版本；请先单独归档后使用新模板。");
        var same = all.Where(d => d.Text("Id") == id).ToArray();
        if (same.Any(d => d.Number("Revision") == revision && d.Text("Fingerprint") != fingerprint)) throw new OperationException("此模板修订号已被占用。");
        if (same.Length == 0 && all.Select(d => d.Text("Id")).Distinct().Count() >= ClientTemplates.MaximumTemplates) throw new OperationException("模板库最多32组。");
        if (snapshot.Text("ParentFingerprint") != "")
        {
            var previous = same.SingleOrDefault(d => d.Number("Revision") == revision - 1);
            if (previous == null || revision != same.Max(d => d.Number("Revision")) + 1 || previous.Text("Fingerprint") != snapshot.Text("ParentFingerprint")) throw new OperationException("模板父版本或修订顺序变化，请重新打开最新版本编辑。");
        }
        else if (revision != 1 && fingerprint != ArchiveStore.Fingerprint(builtin)) throw new OperationException("新模板必须从修订1开始。");
        token.ThrowIfCancellationRequested();
        store.WriteSecret(file, new() { ["Schema"] = 1, ["Fingerprint"] = fingerprint, ["Document"] = snapshot, ["Hashes"] = rendered["Hashes"]!.DeepClone(), ["Dependencies"] = rendered["Dependencies"]!.DeepClone() });
    }
    private async Task<(JsonObject Document, Dictionary<string, string> Files, JsonArray Dependencies)> Materialize(string id, int revision, CancellationToken token)
    {
        var document = Read(id, revision); var file = VersionFile(id, revision);
        if (!File.Exists(file)) await SaveVersionAsync(document, token);
        var record = ReadRecord(file);
        if (!JsonNode.DeepEquals(document["Cores"], CoreIdentities(document.Text("Clients")))) throw new OperationException("模板所固定的核心归档已变化。请审阅并保存新修订，不会静默升级模板依赖。");
        RequireArtifacts(document);
        var rendered = await Render(document, token); var files = new Dictionary<string, string>();
        foreach (var format in document["Bases"]!.AsObject().Select(p => p.Key))
        {
            var hash = rendered.Text("Hashes." + format);
            if (hash != record.Text("Hashes." + format)) throw new OperationException("渲染程序或运行时变化，无法复现固定版本；请审阅新修订。");
            var path = store.Paths.Resolve(Root + "rendered/" + record.Text("Fingerprint") + (format == "Clash" ? ".yaml" : ".json"));
            if (File.Exists(path)) { if (ClientSchemes.SourceFingerprint(path) != hash) throw new OperationException("固定模板文件被外部修改，未覆盖。"); }
            else ArchiveStore.AtomicWrite(path, Encoding.UTF8.GetBytes(rendered.Text("Contents." + format)));
            files[format] = path;
        }
        return (document, files, rendered["Dependencies"]!.DeepClone().AsArray());
    }
    private string DependenciesStamp() => ArchiveStore.Fingerprint(new JsonObject { ["Cores"] = CoreIdentities(), ["Renderer"] = ClientSchemes.SourceFingerprint(store.Paths.Resolve("scripts/client-template-library.py")), ["ReviewRenderer"] = ClientSchemes.SourceFingerprint(store.Paths.Resolve("scripts/client_output_review.py")) });
    public async Task<ClientTemplateReview> PreviewAsync(string schemeId, string templateId, int revision, CancellationToken token)
    {
        ClientSourceBarrier.RequireAvailable(store, "Scheme", schemeId);
        var scheme = store.ReadSecret(SchemeFile(schemeId)); var before = ArchiveStore.Fingerprint(scheme); var sourceBefore = Sources(scheme); var stamp = DependenciesStamp();
        try
        {
            var material = await Materialize(templateId, revision, token); var after = ClientTemplates.ApplyFields(scheme, material.Document, material.Files);
            var signature = Signature(scheme, after, material.Document, stamp);
            if (ArchiveStore.Fingerprint(store.ReadSecret(SchemeFile(schemeId))) != before || stamp != DependenciesStamp()) throw new OperationException("预览期间方案或依赖变化，请重新审阅。");
            var changed = ClientTemplates.SchemeFields.Where(k => !JsonNode.DeepEquals(scheme[k], after[k])).ToArray();
            var diffs = new List<string>();
            foreach (var format in ClientSchemes.Formats(scheme))
            {
                var oldHash = ClientSchemes.SourceFingerprint(scheme.Text(format));
                var result = await tools.RunAsync(python, [store.Paths.Resolve("scripts/client_output_review.py"), "review", "--format", format, "--before", scheme.Text(format), "--after", material.Files[format]], null, TimeSpan.FromSeconds(20), token);
                result.RequireSuccess("原基础配置无法解析，未生成不完整的模板差异。"); var delta = JsonNode.Parse(result.Output)!.AsObject();
                if (delta.Text("BeforeHash") != oldHash || delta.Text("AfterHash") != ClientSchemes.SourceFingerprint(material.Files[format])) throw new OperationException("模板差异文件已变化。");
                diffs.Add((format == "Clash" ? "Mihomo" : "May Route") + "：DNS " + (delta.Flag("DnsChanged") ? "变化" : "保留") + "，规则 " + (delta.Flag("RulesChanged") ? "变化" : "保留") + "，监听 " + (delta.Flag("ListenersChanged") ? "变化" : "保留") + "，其他设置 " + (delta.Flag("SettingsChanged") ? "变化" : "保留"));
            }
            var parameters = material.Document["Parameters"]!;
            var summary = material.Document.Text("Name") + " · 修订 " + revision + "\n" + "变更：" + string.Join("、", changed.Select(k => k switch { "Clash" => "Mihomo基础配置", "SingBox" => "May Route基础配置", "Layout" => "地区／业务分组", "SourceMode" => "基础来源模式", _ => "模板绑定及来源摘要" }).Distinct()) +
                "\nMihomo混合端口 " + parameters.Number("ClashMixedPort") + "；May Route混合端口 " + parameters.Number("RouteMixedPort") + "；局域网监听 " + (parameters.Flag("AllowLan") ? "开启" : "关闭") +
                "\n" + string.Join("\n", diffs) + "\n保留 " + scheme["Nodes"]!.AsArray().Count + " 个节点、凭据、节点组引用、订阅及导出目标。当前基础DNS／规则将由所选版本替换；可在高级编辑中查看完整内容。\n清除旧候选，重新生成、校验和审阅后才能导出。远程规则／GeoData依赖 " + material.Dependencies.Count + " 项，仅检查声明，未下载或证明公网可用。";
            if (ArchiveStore.Fingerprint(store.ReadSecret(SchemeFile(schemeId))) != before || stamp != DependenciesStamp() || !JsonNode.DeepEquals(sourceBefore, Sources(scheme))) throw new OperationException("差异审阅期间方案、基础来源或依赖变化。");
            return new(schemeId, templateId, revision, signature, after, summary);
        }
        finally { scheme.Clear(); }
    }
    private static string Signature(JsonObject before, JsonObject after, JsonObject document, string stamp) => ArchiveStore.Fingerprint(new JsonObject { ["Before"] = before.DeepClone(), ["BeforeSources"] = Sources(before), ["After"] = after.DeepClone(), ["Document"] = document.DeepClone(), ["Dependencies"] = stamp });
    public async Task<string> ApplyAsync(ClientTemplateReview review, CancellationToken token)
    {
        using var held = ClientSourceSync.LockFile(SchemeFile(review.SchemeId));
        var current = await PreviewAsync(review.SchemeId, review.TemplateId, review.Revision, token);
        if (current.Fingerprint != review.Fingerprint || !JsonNode.DeepEquals(current.After, review.After)) throw new OperationException("方案、模板或审阅内容已变化，请重新预览。");
        var before = store.ReadSecret(SchemeFile(review.SchemeId)); var id = Guid.NewGuid().ToString("N");
        if (JsonNode.DeepEquals(ClientTemplates.Fields(before), ClientTemplates.Fields(current.After))) { before.Clear(); current.After.Clear(); return ""; }
        var journal = new JsonObject { ["Schema"] = 1, ["Id"] = id, ["SchemeId"] = review.SchemeId, ["Phase"] = "Prepared", ["Before"] = ClientTemplates.Fields(before), ["After"] = ClientTemplates.Fields(current.After), ["At"] = DateTimeOffset.UtcNow,
            ["BeforeSources"] = Sources(before) };
        journal["BeforeHash"] = ArchiveStore.Fingerprint(journal["Before"]!); journal["AfterHash"] = ArchiveStore.Fingerprint(journal["After"]!);
        token.ThrowIfCancellationRequested(); store.WriteSecret(JournalFile(id), journal);
        try { store.WriteSecret(SchemeFile(review.SchemeId), current.After); journal["Phase"] = "Completed"; store.WriteSecret(JournalFile(id), journal); }
        finally { before.Clear(); current.After.Clear(); }
        return id;
    }
    private static JsonObject Sources(JsonObject scheme)
    {
        var result = new JsonObject(); foreach (var format in ClientSchemes.Formats(scheme)) { var path = scheme.Text(format); if (path != "") result[path] = ClientSchemes.SourceFingerprint(path); } return result;
    }
    public ClientTemplateRestoreReview PreviewRestore(string id)
    {
        var journal = store.ReadSecret(JournalFile(id)); ClientTemplates.ValidateJournal(journal);
        if (journal.Text("Phase") == "RolledBack") throw new OperationException("此应用已经恢复。");
        new ClientSourceSync(store).GuardPending("Scheme", journal.Text("SchemeId")); ClientTemplates.GuardPending(store, "Scheme", journal.Text("SchemeId"), id);
        var current = store.ReadSecret(SchemeFile(journal.Text("SchemeId"))); var fields = ClientTemplates.Fields(current);
        if (ArchiveStore.Fingerprint(fields) != journal.Text("BeforeHash") && ArchiveStore.Fingerprint(fields) != journal.Text("AfterHash")) throw new OperationException("方案基础配置已有其他修改，不覆盖新数据。");
        if (journal["BeforeSources"] is not JsonObject sources || sources.Any(p => ClientSchemes.SourceFingerprint(p.Key) != p.Value?.ToString())) throw new OperationException("原基础来源文件变化或缺失，不恢复到过期来源。");
        _ = ClientTemplates.ReplaceFields(current, journal["Before"]!.AsObject());
        return new(id, ArchiveStore.Fingerprint(new JsonObject { ["Journal"] = journal.DeepClone(), ["Current"] = current.DeepClone() }), "恢复此应用前的基础模板、来源及布局；保留当前节点、订阅、输出规则和导出文件，清除需要重新生成的候选。确认不明时只核对前后身份，不重放应用。");
    }
    public void Restore(ClientTemplateRestoreReview review)
    {
        var journal = store.ReadSecret(JournalFile(review.ApplicationId)); ClientTemplates.ValidateJournal(journal);
        using var held = ClientSourceSync.LockFile(SchemeFile(journal.Text("SchemeId")));
        if (PreviewRestore(review.ApplicationId).Fingerprint != review.Fingerprint) throw new OperationException("恢复审阅后数据发生变化，请重新核对。");
        var current = store.ReadSecret(SchemeFile(journal.Text("SchemeId")));
        if (ArchiveStore.Fingerprint(ClientTemplates.Fields(current)) == journal.Text("AfterHash"))
        { journal["Phase"] = "UndoPrepared"; store.WriteSecret(JournalFile(review.ApplicationId), journal); store.WriteSecret(SchemeFile(journal.Text("SchemeId")), ClientTemplates.ReplaceFields(current, journal["Before"]!.AsObject())); }
        journal["Phase"] = "RolledBack"; store.WriteSecret(JournalFile(review.ApplicationId), journal); current.Clear();
    }
    public void Verify(JsonObject scheme)
    {
        ClientTemplates.GuardPending(store, "Scheme", scheme.Text("Id"));
        if (scheme["TemplateReference"] is not JsonObject reference) return;
        var record = ReadRecord(VersionFile(reference.Text("Id"), reference.Number("Revision")));
        if (reference.Text("Fingerprint") != record.Text("Fingerprint") || !JsonNode.DeepEquals(record.At("Document.Cores"), CoreIdentities(record.Text("Document.Clients")))) throw new OperationException("模板版本或核心依赖变化，请重新选择并审阅模板。");
        foreach (var format in ClientSchemes.Formats(scheme)) if (record.Text("Hashes." + format) != ClientSchemes.SourceFingerprint(scheme.Text(format))) throw new OperationException("已固定的模板来源变化或缺少所选客户端，未继续生成／导出。");
    }
}
