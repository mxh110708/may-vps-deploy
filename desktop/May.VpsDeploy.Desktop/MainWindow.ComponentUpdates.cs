using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private bool UpgradeDetails(StackPanel details, JsonObject options, string relative, string component, string archived, string fixedVersion)
    {
        options.Remove("ReleaseSha256"); options.Remove("TargetVersion");
        var latest = options.Text("Source", "Fixed") == "Latest";
        JsonObject? candidate = null;
        if (latest)
        {
            try { candidate = ComponentUpdates.Candidate(paths, relative, component); }
            catch (OperationException error) { details.Children.Add(Text(error.Message, 14, true)); return false; }
            options["ReleaseSha256"] = ClientSchemes.SourceFingerprint(ComponentUpdates.CandidateFile(paths, relative, component));
        }
        var version = latest ? candidate!.Text("Version") : fixedVersion;
        options["TargetVersion"] = version;
        details.Children.Add(Card(Column(Text("归档版本：" + archived, 14, true), Text("目标版本：" + version, 18),
            Text(latest ? "官方最新稳定版 · 查询时间：" + LocalTime(candidate!.Text("FetchedAt")) : "应用固定版本", 14, true))));
        if (candidate != null)
        {
            details.Children.Add(Text("发行资产：" + candidate.Text("AssetName"), 13, true));
            var digest = Text("SHA256：" + candidate.Text("Sha256"), 12, true); digest.IsTextSelectionEnabled = true; details.Children.Add(digest);
            details.Children.Add(Text("查询结果有效期为 24 小时。执行使用这里锁定的版本和哈希；新发行不会在审阅后自动替换目标。", 13, true));
            if (version == archived) { details.Children.Add(Text("归档已是此稳定版，无需重复升级。可通过健康检查核对实际版本。", 14, true)); return false; }
            if (ComponentUpdates.IsOlder(version, archived)) { details.Children.Add(Text("官方稳定版低于归档版本，自动降级已阻止。请先核对实际版本。", 14, true)); return false; }
        }
        else if (version == archived) details.Children.Add(Text("归档版本已与固定版本一致；继续将重新安装并验收此版本。", 14, true));
        else if (ComponentUpdates.IsOlder(version, archived)) details.Children.Add(Text("固定版本低于归档版本，继续会回到此固定版本。请审阅影响；需要最新版时请选择官方最新稳定版。", 14, true));
        return version != "";
    }
}
