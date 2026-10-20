using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class ComponentUpdates
{
    public static readonly string[] Components = ["xray", "sing_box", "komari_agent", "komari_controller", "cloudflared"];
    public static string Repository(string component) => component switch
    {
        "xray" => "XTLS/Xray-core", "sing_box" => "SagerNet/sing-box", "komari_agent" => "komari-monitor/komari-agent",
        "komari_controller" => "komari-monitor/komari", "cloudflared" => "cloudflare/cloudflared", _ => throw new OperationException("未知升级组件。")
    };
    public static string Label(string component) => component switch { "xray" => "Xray", "sing_box" => "sing-box", "komari_agent" => "Komari Agent", "komari_controller" => "Komari 主控", "cloudflared" => "cloudflared", _ => throw new OperationException("未知升级组件。") };
    public static string ProtocolComponent(string protocol) => protocol switch { "RealityEntry" => "xray", "AnyTlsEntry" or "ShadowsocksLanding" => "sing_box", _ => throw new OperationException("请选择已安装的代理核心。") };
    public static string ScopeComponent(string scope) => scope switch { "KomariAgent" => "komari_agent", "KomariController" => "komari_controller", "Tunnel" => "cloudflared", _ => throw new OperationException("请选择已安装的监控组件。") };
    public static string Component(OperationRequest request) => request.Kind == OperationKind.Upgrade ? ProtocolComponent(request.Options.Text("Protocol")) : ScopeComponent(request.Options.Text("Scope"));
    public static string CandidateFile(AppPaths paths, string relative, string component)
    {
        _ = Repository(component); return SafePath.Resolve(paths.Instance(relative), "component-updates/" + component + ".json");
    }
    public static void ValidateQuery(JsonObject options)
    {
        _ = Repository(options.Text("Component"));
        if (options.Any(p => p.Key is not ("Component" or "Protocol" or "Scope")) || options.ContainsKey("Protocol") && ProtocolComponent(options.Text("Protocol")) != options.Text("Component") || options.ContainsKey("Scope") && ScopeComponent(options.Text("Scope")) != options.Text("Component") || options.ContainsKey("Protocol") && options.ContainsKey("Scope")) throw new OperationException("版本查询对象与组件不一致。");
    }
    public static void ValidateOptions(OperationRequest request)
    {
        var options = request.Options;
        if (options.Text("Source", "Fixed") is not ("Fixed" or "Latest")) throw new OperationException("请选择应用固定版本或官方最新稳定版。");
        if (options.Text("Source", "Fixed") == "Latest" && !Regex.IsMatch(options.Text("ReleaseSha256"), "^[a-f0-9]{64}$")) throw new OperationException("请先查询并审阅官方最新版。");
        if (options.Text("Source", "Fixed") == "Fixed" && options.ContainsKey("ReleaseSha256")) throw new OperationException("固定版本不能混入另一来源的候选材料。");
        if (options.Any(p => !new[] { "Scope", "Action", "Protocol", "TargetVersion", "Source", "ReleaseSha256" }.Contains(p.Key))) throw new OperationException("升级只接受所选来源、版本和已审阅的候选摘要。");
    }
    public static string AssetName(string component, string version) => component switch
    {
        "xray" => "Xray-linux-64.zip", "sing_box" => "sing-box-" + version + "-linux-amd64.tar.gz",
        "komari_agent" => "komari-agent-linux-amd64", "komari_controller" => "komari-linux-amd64", "cloudflared" => "cloudflared-linux-amd64", _ => throw new OperationException("未知升级组件。")
    };
    public static bool IsOlder(string candidate, string installed) => Version.TryParse(candidate.TrimStart('v'), out var target) && Version.TryParse(installed.TrimStart('v'), out var current) && target < current;
    public static string MonitoringVersion(JsonObject plan, JsonObject state, string scope)
    {
        var name = scope == "Tunnel" ? "Cloudflared" : scope;
        var verified = state.Text("MonitoringInventory." + name + ".Version");
        if (verified != "") return verified;
        return scope switch { "KomariAgent" => plan.Text("Komari.AgentVersion"), "KomariController" => state.Text("KomariController.Version", plan.Text("KomariController.Version")), "Tunnel" => state.Text("Cloudflared.Version", plan.Text("Cloudflared.Version")), _ => throw new OperationException("未知监控组件。") };
    }
    public static void ValidateCandidate(JsonObject candidate, string component, bool checkAge = true)
    {
        var version = candidate.Text("Version"); var tag = candidate.Text("Tag");
        if (candidate.Number("SchemaVersion") != 1 || candidate.Text("Component") != component || candidate.Text("Repository") != Repository(component) || candidate.Text("Architecture") != "amd64" || candidate.Text("DigestSource") != "GitHubAssetDigest" || version.Length > 64 || !Regex.IsMatch(version, "^[0-9]+\\.[0-9]+\\.[0-9]+$") || tag != version && tag != "v" + version || candidate.Text("AssetName") != AssetName(component, version) || candidate.Text("Url") != "https://github.com/" + Repository(component) + "/releases/download/" + tag + "/" + AssetName(component, version) || !Regex.IsMatch(candidate.Text("Sha256"), "^[a-f0-9]{64}$") || candidate.Long("Bytes") is < 1 or > 536870912 || candidate.Long("ReleaseId") <= 0 || candidate.Long("AssetId") <= 0) throw new OperationException("官方候选版本、来源或资产身份不匹配。");
        if (!DateTimeOffset.TryParse(candidate.Text("FetchedAt"), out var at) || at > DateTimeOffset.UtcNow.AddMinutes(1) || checkAge && at < DateTimeOffset.UtcNow.AddHours(-24)) throw new OperationException("版本查询超过 24 小时，请重新查询并审阅。");
    }
    public static JsonObject Candidate(AppPaths paths, string relative, string component)
    {
        var file = CandidateFile(paths, relative, component);
        if (!File.Exists(file) || new FileInfo(file).Length > 65536) throw new OperationException("请先查询该组件的官方最新稳定版。");
        var candidate = ArchiveStore.ReadJson(file); ValidateCandidate(candidate, component); return candidate;
    }
    public static JsonObject Versions(AppPaths paths, string relative, OperationRequest request, JsonObject fixedVersions)
    {
        ValidateOptions(request); var component = Component(request);
        if (request.Options.Text("Source", "Fixed") != "Latest") return fixedVersions;
        var candidate = Candidate(paths, relative, component);
        if (request.Options.Text("ReleaseSha256") != ClientSchemes.SourceFingerprint(CandidateFile(paths, relative, component)) || request.Options.Text("TargetVersion") != candidate.Text("Version")) throw new OperationException("官方候选材料在审阅后变化，请重新查询并审阅。", code: "ComponentReleaseChanged");
        var versions = fixedVersions.DeepClone().AsObject();
        versions.Put(component + ".version", JsonValue.Create(candidate.Text("Version")));
        versions.Put(component + ".assets.amd64", new JsonObject { ["name"] = candidate.Text("AssetName"), ["sha256"] = candidate.Text("Sha256"), ["bytes"] = candidate.Long("Bytes"), ["url"] = candidate.Text("Url") });
        return versions;
    }
}
