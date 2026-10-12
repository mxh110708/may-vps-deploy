using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private void RecordComponentUpgrade(Context c, JsonObject versions)
    {
        var component = ComponentUpdates.Component(c.Request);
        var scope = c.Request.Kind == OperationKind.Upgrade ? c.Request.Options.Text("Protocol") : c.Request.Options.Text("Scope");
        c.State.Put("ComponentUpgrades." + scope, new JsonObject
        {
            ["Component"] = component, ["Version"] = versions.Text(component + ".version"), ["Source"] = c.Request.Options.Text("Source", "Fixed"),
            ["AssetName"] = versions.Text(component + ".assets.amd64.name"), ["Sha256"] = versions.Text(component + ".assets.amd64.sha256"), ["TaskId"] = c.Id, ["At"] = DateTimeOffset.UtcNow
        });
    }
    private async Task CheckComponentUpdate(Context c)
    {
        ComponentUpdates.ValidateQuery(c.Request.Options); var component = c.Request.Options.Text("Component");
        await c.TrackStep("component-release-check", async () =>
        {
            await c.VerifySsh(c.Port, "root");
            var response = await c.Run("component-release-latest.sh", new() { ["COMPONENT"] = component }, false, 60);
            var candidate = JsonNode.Parse(RemoteAssets.Marker(response.Output, "COMPONENT_RELEASE"))!.AsObject();
            ComponentUpdates.ValidateCandidate(candidate, component);
            ArchiveStore.WriteJson(ComponentUpdates.CandidateFile(store.Paths, c.Request.InstanceRelativePath, component), candidate);
            c.State.Put("LastComponentRelease." + component, candidate.DeepClone()); c.Save();
            c.Report("component-release-check", ComponentUpdates.Label(component) + " 官方最新稳定版：" + candidate.Text("Version") + "。具体资产与 SHA256 已锁定；当前未执行升级。");
        });
    }
}
