using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class ClientTemplates
{
    public const int MaximumVersions = 32;
    public const int MaximumTemplates = 32;
    public const int MaximumBaseBytes = 256 * 1024;
    public static readonly string[] SchemeFields = ["Clash", "SingBox", "Layout", "SourceMode", "SourceFingerprints", "TemplateReference", "AuthorityNodes"];
    public static string Id(string id) => Regex.IsMatch(id, "^[a-f0-9]{32}$") ? id : throw new OperationException("模板身份无效。");
    public static int Revision(int revision) => revision is >= 1 and <= MaximumVersions ? revision : throw new OperationException("模板修订号超出1–32范围。");
    public static JsonObject DefaultParameters() => new()
    {
        ["ClashMixedPort"] = 7890, ["RouteMixedPort"] = 2080, ["AllowLan"] = false,
        ["LogLevel"] = "info", ["Mode"] = "rule", ["ClashIpv6"] = true, ["TunMtu"] = 0
    };
    public static void Validate(JsonObject document)
    {
        string[] names = ["Schema", "Id", "Revision", "Name", "ParentFingerprint", "Clients", "Parameters", "Layout", "Bases", "Cores"];
        if (document.Count != names.Length || document.Any(p => !names.Contains(p.Key)) || document.Number("Schema") != 1) throw new OperationException("模板包含未知或缺少字段。");
        _ = Id(document.Text("Id")); _ = Revision(document.Number("Revision"));
        if (document.Text("Name").Length is < 1 or > 80 || document.Text("Name").Any(char.IsControl) || document.Text("ParentFingerprint") != "" && !RouteDiagnostics.Digest(document.Text("ParentFingerprint"))) throw new OperationException("模板名称或父版本摘要无效。");
        var formats = ClientSchemes.Formats(new JsonObject { ["OutputClients"] = document.Text("Clients") });
        var parameters = document["Parameters"] as JsonObject ?? throw new OperationException("缺少模板参数。");
        var defaults = DefaultParameters();
        if (parameters.Count != defaults.Count || parameters.Any(p => !defaults.ContainsKey(p.Key))) throw new OperationException("模板参数包含未知或缺少字段。");
        foreach (var key in new[] { "ClashMixedPort", "RouteMixedPort", "TunMtu" })
            if (parameters[key] is not JsonValue v || !v.TryGetValue<int>(out var n) || (key == "TunMtu" ? n != 0 && n is < 1280 or > 9000 : n is < 1 or > 65535)) throw new OperationException("监听端口须为1–65535，MTU为0或1280–9000。");
        foreach (var key in new[] { "AllowLan", "ClashIpv6" }) if (parameters[key] is not JsonValue v || !v.TryGetValue<bool>(out _)) throw new OperationException("模板开关必须为布尔值。");
        if (parameters.Text("LogLevel") is not ("debug" or "info" or "warn" or "error") || parameters.Text("Mode") is not ("rule" or "global" or "direct")) throw new OperationException("日志等级或路由模式无效。");
        if (document["Bases"] is not JsonObject bases || bases.Count != formats.Length || bases.Any(p => !formats.Contains(p.Key))) throw new OperationException("模板基础内容必须对应所选客户端。");
        foreach (var item in bases)
            if (item.Value is not JsonValue v || !v.TryGetValue<string>(out var text) || System.Text.Encoding.UTF8.GetByteCount(text) is < 2 or > MaximumBaseBytes) throw new OperationException("基础模板为空或超过256 KiB。");
        var requiredCores = Cores(document.Text("Clients"));
        if (document["Cores"] is not JsonObject cores || cores.Count != requiredCores.Length || cores.Any(p => !requiredCores.Contains(p.Key) || p.Value is not JsonObject || !RouteDiagnostics.Digest(p.Value.Text("Identity")) || p.Value.Text("Version").Length is < 1 or > 80)) throw new OperationException("模板需绑定所选客户端的核心版本和归档摘要。");
        ValidateLayout(document["Layout"] as JsonObject ?? throw new OperationException("缺少模板布局。"));
    }
    public static string[] Cores(string clients) => clients switch { "Clash" => ["mihomo"], "SingBox" => ["sing-box", "may-core"], "Both" => ["mihomo", "sing-box", "may-core"], _ => throw new OperationException("模板客户端范围无效。") };
    public static void ValidateLayout(JsonObject layout)
    {
        if (layout.Number("schema_version") != 2 || layout.Text("business_policy") != "GoogleServices.v1" || layout["region_groups"] is not JsonArray regions || regions.Count is < 1 or > 32 || layout["business_groups"] is not JsonArray businesses || businesses.Count is < 1 or > 64 || layout["guard_groups"] is not JsonArray guards || guards.Count > 32) throw new OperationException("模板布局版本、地区或分组数量无效。");
        var names = new[] { layout.Text("default_exit_group"), layout.Text("direct_group") }.Concat(layout.Strings("region_groups")).Concat(businesses.Select(g => g!.Text("name"))).Concat(guards.Select(g => g!.Text("name"))).ToArray();
        if (names.Any(n => n.Length is < 1 or > 80 || n.Any(char.IsControl) || n is "DIRECT" or "BLOCK") || names.Distinct(StringComparer.Ordinal).Count() != names.Length) throw new OperationException("模板组名称无效或重复。");
        var allowed = new[] { layout.Text("default_exit_group"), layout.Text("direct_group") }.Concat(layout.Strings("region_groups")).Concat(["DIRECT", "BLOCK"]).ToHashSet(StringComparer.Ordinal);
        foreach (var group in businesses)
        {
            if (group is not JsonObject g || !allowed.Contains(g.Text("default")) || g["order"] is not JsonArray order || order.Count > 64 || order.Any(n => n == null || !allowed.Contains(n.ToString()))) throw new OperationException("业务组默认值／顺序只能引用模板中的地区、出口组或DIRECT／BLOCK，不能引用具体节点。");
        }
        foreach (var group in guards)
            if (group is not JsonObject g || g["members"] is not JsonArray members || members.Count is < 1 or > 64 || members.Any(n => n == null || !allowed.Contains(n.ToString()))) throw new OperationException("保护组含未知依赖。");
        if (regions.Any(n => n is not JsonValue v || !v.TryGetValue<string>(out _)) || layout["default_exit_members"] is not JsonArray exits || exits.Any(n => n == null || !(layout.Strings("region_groups").Append("DIRECT")).Contains(n.ToString()))) throw new OperationException("默认出口包含未知或循环依赖。");
    }
    public static JsonObject Fields(JsonObject scheme)
    {
        var fields = new JsonObject(); foreach (var key in SchemeFields) if (scheme.ContainsKey(key)) fields[key] = scheme[key]?.DeepClone(); return fields;
    }
    public static JsonObject ReplaceFields(JsonObject scheme, JsonObject fields)
    {
        if (fields.Any(p => !SchemeFields.Contains(p.Key))) throw new OperationException("模板变更超出基础配置与布局范围。");
        var result = scheme.DeepClone().AsObject(); foreach (var key in SchemeFields) { result.Remove(key); if (fields.ContainsKey(key)) result[key] = fields[key]?.DeepClone(); }
        result.Remove("Candidate"); RequireNodeGroups(result); return result;
    }
    public static void RequireNodeGroups(JsonObject scheme)
    {
        ValidateLayout(scheme["Layout"]!.AsObject()); var regions = scheme["Layout"]!.Strings("region_groups");
        foreach (var n in scheme["Nodes"]!.AsArray())
            if (!regions.Contains(n!.Text(n.Text("kind") == "landing" ? "transit_group" : "region_group"))) throw new OperationException("模板地区不包含现有节点归属；请先调整模板布局，节点不会被静默改组或删除。");
    }
    public static JsonObject ApplyFields(JsonObject scheme, JsonObject document, IReadOnlyDictionary<string, string> rendered)
    {
        Validate(document); foreach (var format in ClientSchemes.Formats(scheme)) if (!rendered.ContainsKey(format)) throw new OperationException("所选模板缺少当前方案所需客户端。");
        var fields = Fields(scheme); var sources = new JsonObject();
        foreach (var pair in rendered) { fields[pair.Key] = pair.Value; sources[pair.Key] = ClientSchemes.SourceFingerprint(pair.Value); }
        fields["Layout"] = document["Layout"]!.DeepClone(); fields["SourceMode"] = "GenericTemplate"; fields.Remove("AuthorityNodes"); fields["SourceFingerprints"] = sources;
        fields["TemplateReference"] = new JsonObject { ["Id"] = document.Text("Id"), ["Revision"] = document.Number("Revision"), ["Fingerprint"] = ArchiveStore.Fingerprint(document) };
        return ReplaceFields(scheme, fields);
    }
    public static void GuardPending(ArchiveStore store, string? kind, string? id, string? except = null)
    {
        foreach (var journal in Journals(store))
            if (journal.Text("Id") != except && journal.Text("Phase") is "Prepared" or "UndoPrepared" && (kind == null || kind == "Scheme" && journal.Text("SchemeId") == id)) throw new OperationException("此方案有待核对的模板应用／恢复，请先在模板库恢复。", true, "TemplateNeedsRecovery");
    }
    public static IEnumerable<JsonObject> Journals(ArchiveStore store)
    {
        var directory = store.Paths.Resolve("private/client-templates/applications"); if (!Directory.Exists(directory)) yield break;
        SafePath.CheckTree(directory);
        foreach (var file in Directory.EnumerateFiles(directory, "*.private.json"))
        {
            if (new FileInfo(file).Length > 3 * 1024 * 1024) throw new OperationException("模板事务超过大小限制。");
            var value = store.ReadSecret(file); ValidateJournal(value);
            if (Path.GetFileName(file) != value.Text("Id") + ".private.json") throw new OperationException("模板事务文件身份不符。"); yield return value;
        }
    }
    public static void ValidateJournal(JsonObject value)
    {
        _ = Id(value.Text("Id")); _ = Id(value.Text("SchemeId"));
        if (value.Number("Schema") != 1 || value.Text("Phase") is not ("Prepared" or "Completed" or "UndoPrepared" or "RolledBack") || value["Before"] is not JsonObject before || value["After"] is not JsonObject after || before.Any(p => !SchemeFields.Contains(p.Key)) || after.Any(p => !SchemeFields.Contains(p.Key)) || value.Text("BeforeHash") != ArchiveStore.Fingerprint(before) || value.Text("AfterHash") != ArchiveStore.Fingerprint(after)) throw new OperationException("模板事务格式或范围无效，保留材料。");
    }
}
