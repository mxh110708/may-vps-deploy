using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class InstallationVersions
{
    public static string[] DeploymentComponents(JsonObject plan) => DeploymentPlans.Roles[..3].Where(role => DeploymentPlans.Uses(plan, role))
        .Select(ComponentUpdates.ProtocolComponent).Concat(plan.Flag("Komari.Enabled") ? ["komari_agent"] : Array.Empty<string>()).Distinct().ToArray();
    public static string[] AdditionalComponents(JsonObject options) => ComponentInstallations.Selected(options)
        .Select(component => DeploymentPlans.Roles[..3].Contains(component) ? ComponentUpdates.ProtocolComponent(component) : ComponentUpdates.ScopeComponent(component)).Distinct().ToArray();
    public static JsonObject Selection(string source, JsonObject fixedVersions)
    {
        if (source is not ("Fixed" or "Latest")) throw new OperationException("请选择应用固定版本或官方最新稳定版。");
        return new() { ["Source"] = source, ["AssetPin"] = ArchiveStore.Fingerprint(fixedVersions), ["FixedVersions"] = fixedVersions.DeepClone(), ["Candidates"] = new JsonObject() };
    }
    public static JsonObject Resolve(JsonObject? selection, string[] components, JsonObject fixedVersions, bool accepted = false)
    {
        if (selection == null) return fixedVersions;
        var source = selection.Text("Source");
        if (source is not ("Fixed" or "Latest") || selection.Any(p => p.Key is not ("Source" or "AssetPin" or "FixedVersions" or "Candidates")) || selection["FixedVersions"] is not JsonObject snapshot || selection["Candidates"] is not JsonObject candidates || !Regex.IsMatch(selection.Text("AssetPin"), "^[a-f0-9]{64}$") || ArchiveStore.Fingerprint(snapshot) != selection.Text("AssetPin") || !accepted && ArchiveStore.Fingerprint(fixedVersions) != selection.Text("AssetPin"))
            throw new OperationException("安装版本清单已变化，请重新选择来源并审阅。", code: "InstallationVersionsChanged");
        if (components.Any(component => !ComponentUpdates.Components.Contains(component)) || components.Distinct().Count() != components.Length || source == "Fixed" && candidates.Count != 0 || source == "Latest" && (candidates.Count != components.Length || candidates.Any(p => !components.Contains(p.Key) || p.Value is not JsonObject)))
            throw new OperationException("安装候选与所选组件不一致，请重新查询。", code: "InstallationVersionsChanged");
        var result = snapshot.DeepClone().AsObject();
        foreach (var component in components)
        {
            if (source == "Fixed") continue;
            var candidate = candidates[component]!.AsObject();
            ComponentUpdates.ValidateCandidate(candidate, component, !accepted);
            result.Put(component + ".version", JsonValue.Create(candidate.Text("Version")));
            result.Put(component + ".assets.amd64", new JsonObject { ["name"] = candidate.Text("AssetName"), ["sha256"] = candidate.Text("Sha256"), ["bytes"] = candidate.Long("Bytes"), ["url"] = candidate.Text("Url") });
        }
        return result;
    }
    public static JsonObject Additional(JsonObject options, JsonObject fixedVersions)
    {
        if (options.Text("VersionSource", "Fixed") is not ("Fixed" or "Latest")) throw new OperationException("安装版本来源无效。");
        var selection = options["InstallationVersions"] as JsonObject;
        if (options.Text("VersionSource", "Fixed") == "Latest" && selection == null || selection != null && selection.Text("Source") != options.Text("VersionSource", "Fixed")) throw new OperationException("请先查询并锁定本轮安装版本。");
        return Resolve(selection, AdditionalComponents(options), fixedVersions);
    }
    public static void ApplyPlan(JsonObject plan, JsonObject versions, string[] components, string source)
    {
        if (components.Contains("xray")) { plan.Put("Reality.XrayVersion", JsonValue.Create(versions.Text("xray.version"))); plan.Put("Reality.XrayVersionChannel", JsonValue.Create(source == "Latest" ? "OfficialStable" : "FixedVerified")); }
        if (components.Contains("sing_box"))
        {
            if (DeploymentPlans.Uses(plan, "AnyTlsEntry")) plan.Put("AnyTls.SingBoxVersion", JsonValue.Create(versions.Text("sing_box.version")));
            if (DeploymentPlans.Uses(plan, "ShadowsocksLanding")) plan.Put("Shadowsocks.SingBoxVersion", JsonValue.Create(versions.Text("sing_box.version")));
        }
        if (components.Contains("komari_agent")) plan.Put("Komari.AgentVersion", JsonValue.Create(versions.Text("komari_agent.version")));
    }
    public static string Summary(JsonObject selection, string[] components)
    {
        var versions = Resolve(selection, components, selection["FixedVersions"]!.AsObject(), true);
        return string.Join("\n", components.Select(component => ComponentUpdates.Label(component) + " " + versions.Text(component + ".version") + " · " + (selection.Text("Source") == "Latest" ? "官方稳定版（查询时）" : "应用固定版") + "\n资产：" + versions.Text(component + ".assets.amd64.name") + "\nSHA256：" + versions.Text(component + ".assets.amd64.sha256")));
    }
}
