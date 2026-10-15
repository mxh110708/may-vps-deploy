using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement InstallationVersionFields(JsonObject model, string key)
    {
        if (model.Text(key) == "") model[key] = "Fixed";
        return Column(SectionHeading("安装版本", Symbol.Download),
            Choice("安装版本来源", model, key, [("Fixed", "应用固定版本（默认）"), ("Latest", "官方最新稳定版（联网查询）")]),
            Text("最新版在审阅前查询，锁定本轮各组件的具体版本和 SHA256；查询本身不安装软件。审阅中可核对版本，继续部署沿用已锁定版本。", 14, true));
    }
    private async Task<JsonObject> SelectInstallationVersions(string source, string[] components)
    {
        var selection = InstallationVersions.Selection(source, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")));
        if (source == "Latest" && components.Length > 0)
        {
            await RunBackground("查询并锁定安装版本", async token =>
            {
                var runner = new ExternalToolRunner();
                foreach (var component in components)
                {
                    token.ThrowIfCancellationRequested(); taskText.Text = "查询安装版本 · " + ComponentUpdates.Label(component);
                    var result = await runner.RunAsync(paths.Resolve("runtime/python/python.exe"), [paths.Resolve("scripts/component-releases.py"), "--component", component, "--proxy", settings.Text("UpdateProxy", "")], null, TimeSpan.FromSeconds(45), token);
                    if (result.ExitCode != 0)
                    {
                        var code = RemoteAssets.Marker(result.Output, "COMPONENT_RELEASE_FAILURE");
                        throw new OperationException("无法查询 " + ComponentUpdates.Label(component) + " 官方稳定版，请核对联网和设置中的更新代理；本次未安装组件。", code: code);
                    }
                    var candidate = JsonNode.Parse(RemoteAssets.Marker(result.Output, "COMPONENT_RELEASE"))!.AsObject();
                    ComponentUpdates.ValidateCandidate(candidate, component); selection["Candidates"]![component] = candidate;
                }
            });
        }
        _ = InstallationVersions.Resolve(selection, components, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")));
        return selection;
    }
}
