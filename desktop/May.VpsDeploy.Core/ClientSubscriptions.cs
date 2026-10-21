using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientSourceChange(string Kind, string Name, string Detail);
public sealed record ClientSourcePreview(string SchemeFingerprint, JsonObject Source, JsonArray Nodes, IReadOnlyList<ClientSourceChange> Changes, IReadOnlyList<string> Errors)
{
    public bool Ready => Errors.Count == 0;
}

public static class ClientSubscriptions
{
    public static JsonObject New(string region) => new() { ["Id"] = Guid.NewGuid().ToString("N"), ["Name"] = "新订阅来源", ["Url"] = "", ["Region"] = region, ["Role"] = "Auto", ["Network"] = "System", ["Proxy"] = "" };
    public static Uri Validate(JsonObject source)
    {
        if (!Guid.TryParseExact(source.Text("Id"), "N", out _) || source.Text("Name").Length is < 1 or > 100 || source.Text("Name").Any(char.IsControl)) throw new OperationException("来源名称或标识无效。");
        var address = source.Text("Url");
        if (address.Length > 4096 || address.Any(char.IsControl) || !Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.UserInfo != "" || uri.Fragment != "" || uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)) throw new OperationException("订阅地址须为 HTTPS（本机可用 HTTP），不支持内嵌账号密码或片段。");
        if (source.Text("Network", "System") is not ("System" or "Direct" or "Proxy")) throw new OperationException("来源下载方式无效。");
        if (source.Text("Network") == "Proxy")
        {
            if (!Uri.TryCreate(source.Text("Proxy"), UriKind.Absolute, out var proxy) || proxy.Scheme is not ("http" or "https" or "socks5") || proxy.UserInfo != "" || proxy.Port is < 1 or > 65535 || proxy.AbsolutePath is not ("" or "/") || proxy.Query != "" || proxy.Fragment != "") throw new OperationException("代理须为无认证的 HTTP、HTTPS 或 SOCKS5 地址。");
        }
        return uri;
    }
    public static string Label(JsonObject source)
    { var uri = Validate(source); return source.Text("Name") + " · " + uri.IdnHost; }
    public static string Decode(string content)
    {
        if (content.Length > 524288) throw new OperationException("订阅响应超过 512 KiB。");
        var text = content.Trim().TrimStart('\uFEFF');
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            try { var encoded = string.Concat(text.Where(c => !char.IsWhiteSpace(c))).Replace('-', '+').Replace('_', '/'); var bytes = Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '=')); if (bytes.Length > ClientNodeImport.MaximumCharacters) throw new OperationException("解码后的节点列表过大。"); text = new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF'); }
            catch (Exception error) when (error is FormatException or ArgumentException) { throw new OperationException("来源不是受支持的纯文本或 Base64 分享链接列表；Clash YAML / sing-box JSON 请使用读取现有配置。"); }
        }
        if (text.Length > ClientNodeImport.MaximumCharacters || text.StartsWith('<') || text.StartsWith('{') || text.StartsWith("proxies:", StringComparison.Ordinal)) throw new OperationException("来源不是本轮支持的分享链接列表，或解码后过大。");
        return text;
    }
    public static ClientSourcePreview Preview(JsonObject scheme, JsonObject definition, string content)
    {
        Validate(definition); var source = definition.DeepClone().AsObject(); var errors = new List<string>(); var changes = new List<ClientSourceChange>();
        if ((scheme["NodeSources"] as JsonArray ?? []).Any(s => s!.Text("Id") != source.Text("Id") && s.Text("Url") == source.Text("Url"))) errors.Add("此地址已有订阅来源，请刷新现有来源，避免重复管理。");
        var parseScheme = scheme.DeepClone().AsObject(); parseScheme["Nodes"] = new JsonArray();
        var parsed = ClientNodeImport.Preview(Decode(content), parseScheme, source.Text("Region"), source.Text("Role", "Auto"));
        foreach (var row in parsed.Rows.Where(r => r.Status == "Rejected")) errors.Add("第 " + row.Line + " 行：" + row.Message);
        if (parsed.Accepted == 0) errors.Add("来源没有可用节点，不会清空旧节点。");
        var originals = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        var owned = originals.Where(n => n.Text("Source.Kind") == "Subscription" && n.Text("Source.Id") == source.Text("Id")).ToArray();
        var matched = new HashSet<JsonObject>(); var replacements = new Dictionary<JsonObject, JsonObject?>(); var added = new List<JsonObject>();
        foreach (var fresh in parsed.Rows.Where(r => r.Status == "Ready").Select(r => r.Node!))
        {
            var fingerprint = ClientNodeImport.ConnectionFingerprint(fresh); var originalName = fresh.Text("Source.OriginalName", fresh.Text("name"));
            var exact = owned.Where(n => !matched.Contains(n) && n.Text("Source.Fingerprint") == fingerprint).ToArray();
            var similar = owned.Where(n => !matched.Contains(n) && n.Text("Source.OriginalName") == originalName && n.Text("sing_box.type") == fresh.Text("sing_box.type") && n.Text("sing_box.server") == fresh.Text("sing_box.server") && n.Number("sing_box.server_port") == fresh.Number("sing_box.server_port")).ToArray();
            if (exact.Length > 1 || exact.Length == 0 && similar.Length > 1) { errors.Add("来源身份存在歧义：" + originalName); continue; }
            var old = exact.SingleOrDefault() ?? (similar.Length == 1 ? similar[0] : null);
            if (old == null)
            {
                if (originals.Any(n => n.Text("Source.Id") != source.Text("Id") && ClientNodeImport.ConnectionFingerprint(n) == fingerprint)) { changes.Add(new("Existing", originalName, "已有相同外部或受管连接，保留原归属，不接管或覆盖。")); continue; }
                var next = fresh.DeepClone().AsObject(); Stamp(next, source, originalName, fingerprint); added.Add(next); changes.Add(new("Added", originalName, Brief(fresh) + " · " + (fresh.Text("kind") == "entry" ? "入口" : "落地"))); continue;
            }
            matched.Add(old); var localChanged = ClientNodeImport.ConnectionFingerprint(old) != old.Text("Source.Fingerprint"); var upstreamChanged = fingerprint != old.Text("Source.Fingerprint");
            if (localChanged && upstreamChanged) { errors.Add("节点“" + old.Text("name") + "”本地与来源均有参数修改。请先将其转为手动节点，再刷新，或取消本次更新。"); changes.Add(new("Conflict", old.Text("name"), "本地修改未被覆盖")); continue; }
            var replacement = old.DeepClone().AsObject();
            if (upstreamChanged) { replacement["clash"] = fresh["clash"]!.DeepClone(); replacement["sing_box"] = fresh["sing_box"]!.DeepClone(); }
            var oldImportedName = old.Text("Source.ImportedDisplayName", old.Text("Source.OriginalName"));
            var display = old.Text("name") == oldImportedName && originalName != old.Text("Source.OriginalName") ? fresh.Text("name") : old.Text("name");
            replacement["name"] = display; replacement["clash"]!["name"] = display; replacement["sing_box"]!["tag"] = display;
            Stamp(replacement, source, originalName, fingerprint); replacement["Source"]!["ImportedDisplayName"] = old.Text("name") == oldImportedName ? display : oldImportedName;
            replacement["Source"]!["Modified"] = localChanged;
            replacements[old] = replacement;
            var sourceRenamed = originalName != old.Text("Source.OriginalName");
            changes.Add(new(upstreamChanged ? "Changed" : sourceRenamed ? "Renamed" : "Unchanged", old.Text("name"), upstreamChanged ? Brief(fresh) + " · " + ChangedFields(old, fresh) + "；保留节点 ID、用途、地区与出口标注" : sourceRenamed ? "来源名称 → " + originalName + "；输出显示名 → " + display : localChanged ? "来源未变，保留本地参数修改" : "连接未变化"));
        }
        foreach (var old in owned.Where(n => !matched.Contains(n)))
        {
            if (ClientNodeImport.ConnectionFingerprint(old) != old.Text("Source.Fingerprint")) { errors.Add("来源移除了本地已修改的节点“" + old.Text("name") + "”，请先转为手动节点再刷新。"); changes.Add(new("Conflict", old.Text("name"), "本地修改未删除")); }
            else { replacements[old] = null; changes.Add(new("Removed", old.Text("name"), "来源已移除此连接；将显示受影响的默认出口")); }
        }
        var output = new JsonArray(); var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var old in originals)
        {
            var value = replacements.TryGetValue(old, out var replacement) ? replacement : old;
            if (value == null) continue;
            var node = value.DeepClone().AsObject(); if (!names.Add(node.Text("name"))) errors.Add("来源更新导致名称冲突：" + node.Text("name")); output.Add(node);
        }
        foreach (var node in added)
        {
            var baseline = node.Text("name"); var name = baseline; var suffix = 2;
            while (!names.Add(name)) { var tail = " (" + suffix++ + ")"; name = baseline[..Math.Min(baseline.Length, 120 - tail.Length)] + tail; }
            node["name"] = name; node["clash"]!["name"] = name; node["sing_box"]!["tag"] = name; node["Source"]!["ImportedDisplayName"] = name; output.Add(node);
            if (name != baseline) changes.Add(new("Renamed", baseline, "与其他节点重名，新增节点显示名调整为：" + name));
        }
        foreach (var old in originals.Where(replacements.ContainsKey))
            if (replacements[old] == null)
            {
                foreach (var impact in ClientTopology.RemovalImpact(scheme, old)) changes.Add(new("Impact", old.Text("name"), impact));
                foreach (var dependent in originals.Where(n => n != old && (n.Text("sing_box.detour") == old.Text("name") || n.Text("clash.dialer-proxy") == old.Text("name")))) changes.Add(new("Impact", dependent.Text("name"), "原生上游节点将被移除，请先调整此连接。"));
            }
        var remainingRegions = output.OfType<JsonObject>().Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
        foreach (var region in ClientTopology.Regions(scheme).Where(r => !remainingRegions.Contains(r.Name)))
            foreach (var group in scheme["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>().Where(g => g.Text("default") == region.Name)) changes.Add(new("Impact", region.Name, "业务组“" + group.Text("name") + "”的默认入口组将为空，须重新指定。"));
        source["LastFetchedAt"] = DateTimeOffset.UtcNow.ToString("O"); source["ContentHash"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes(content));
        return new(ArchiveStore.Fingerprint(scheme), source, output, changes, errors);
    }
    private static void Stamp(JsonObject node, JsonObject source, string originalName, string fingerprint)
    {
        var date = node.Text("Source.ImportedAt", DateTimeOffset.UtcNow.ToString("O"));
        node["Source"] = new JsonObject { ["Kind"] = "Subscription", ["Id"] = source.Text("Id"), ["OriginalName"] = originalName, ["ImportedDisplayName"] = node.Text("name"), ["Protocol"] = node.Text("sing_box.type"), ["Fingerprint"] = fingerprint, ["ImportedAt"] = date, ["Modified"] = false };
    }
    private static string Brief(JsonObject node)
    { var host = node.Text("sing_box.server"); return node.Text("sing_box.type") + " · " + (host.Contains(':') ? "[" + host + "]" : host) + ":" + node.Number("sing_box.server_port"); }
    private static string ChangedFields(JsonObject previous, JsonObject current)
    {
        var changed = new List<string>();
        if (previous.Text("sing_box.password") != current.Text("sing_box.password") || previous.Text("sing_box.uuid") != current.Text("sing_box.uuid")) changed.Add("鉴权信息变化（不展示值）");
        if (previous.Text("sing_box.method") != current.Text("sing_box.method")) changed.Add("加密方法变化");
        if ((previous.At("sing_box.tls")?.ToJsonString() ?? "") != (current.At("sing_box.tls")?.ToJsonString() ?? "")) changed.Add("TLS / Reality 参数变化");
        return changed.Count == 0 ? "其他连接参数变化" : string.Join("、", changed);
    }
    public static void Apply(JsonObject scheme, ClientSourcePreview preview)
    {
        if (!preview.Ready) throw new OperationException("来源预览仍有错误或本地修改冲突，未更新方案。");
        if (ArchiveStore.Fingerprint(scheme) != preview.SchemeFingerprint) throw new OperationException("方案已变化，请重新获取来源并预览。");
        var before = scheme.DeepClone().AsObject(); var oldNodes = scheme["Nodes"]!.AsArray();
        var defaults = scheme["Layout"]!["business_groups"]!.AsArray(); var names = new Dictionary<string, string>(StringComparer.Ordinal); var removedNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var old in oldNodes.OfType<JsonObject>())
        {
            var next = preview.Nodes.OfType<JsonObject>().SingleOrDefault(n => n.Text("Id") != "" && n.Text("Id") == old.Text("Id"));
            if (next != null && next.Text("name") != old.Text("name")) names[old.Text("name")] = next.Text("name");
            if (next == null && old.Text("Source.Id") == preview.Source.Text("Id")) removedNames.Add(old.Text("name"));
        }
        ClientSchemes.RemapNodeReferences(scheme, names, removedNames);
        scheme["Nodes"] = preview.Nodes.DeepClone();
        foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>())
            foreach (var key in new[] { "sing_box.detour", "clash.dialer-proxy" }) if (names.TryGetValue(node.Text(key), out var renamed)) node.Put(key, renamed);
        var active = ClientTopology.Regions(scheme).Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var removed in ClientTopology.Regions(before).Select(r => r.Name).Where(r => !active.Contains(r))) foreach (var group in defaults.OfType<JsonObject>()) if (group.Text("default") == removed) group["default"] = "";
        if (scheme["NodeSources"] is not JsonArray) scheme["NodeSources"] = new JsonArray(); var sources = scheme["NodeSources"]!.AsArray();
        var index = sources.ToList().FindIndex(s => s!.Text("Id") == preview.Source.Text("Id")); if (index < 0) sources.Add(preview.Source.DeepClone()); else sources[index] = preview.Source.DeepClone();
        if (ArchiveStore.Fingerprint(before["Nodes"]!) != ArchiveStore.Fingerprint(scheme["Nodes"]!) || ArchiveStore.Fingerprint(before["Layout"]!) != ArchiveStore.Fingerprint(scheme["Layout"]!)) scheme.Remove("Candidate");
    }
    public static void Detach(JsonObject node)
    { if (node.Text("Source.Kind") != "Subscription") throw new OperationException("此节点不属于订阅来源。"); node["Source"] = new JsonObject { ["Kind"] = "Manual", ["DetachedAt"] = DateTimeOffset.UtcNow.ToString("O") }; }
}
