using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private static void RecordInstalledProgram(Context c, string component, JsonObject versions, string? scope = null)
    {
        var selection = c.Request.Kind == OperationKind.InstallComponent ? c.Request.Options["InstallationVersions"] as JsonObject : c.Plan["InstallationVersions"] as JsonObject;
        c.State.Put("InstalledProgramVersions." + (scope ?? component), new JsonObject { ["Component"] = component, ["Version"] = versions.Text(component + ".version"), ["AssetName"] = versions.Text(component + ".assets.amd64.name"), ["Sha256"] = versions.Text(component + ".assets.amd64.sha256"), ["Source"] = selection?.Text("Source", "Fixed") ?? "Fixed", ["TaskId"] = c.Id, ["At"] = DateTimeOffset.UtcNow });
        c.Save();
    }
}
