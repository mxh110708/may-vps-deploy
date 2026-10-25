using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task ConfigureUdpForwarding(Context c)
    {
        var preview = UdpForwarding.Prepare(store, c.Request); var action = c.Request.Options.Text("Action");
        async Task<JsonObject> Read()
        {
            var response = await c.Run("udp-forward-read.sh", new() { ["ARCHIVED_HASH"] = preview.ExpectedHash }, marker: "UDP_FORWARD_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "UDP_FORWARD_STATE"))!.AsObject();
        }
        await c.TrackStep("udp-forward-preflight", async () =>
        {
            var audit = await c.Run("audit.sh");
            Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
            await VerifyManagement(c);
            if ((await Read()).Text("Hash") != preview.ExpectedHash) throw new OperationException("UDP 转发实际资源与归档不同，未写入服务器。", code: "UdpForwardRemoteDrift");
            if (action != "Check")
            {
                await c.Run("udp-forward-read.sh", new() { ["CANDIDATE_JSON"] = preview.Configuration.ToJsonString(), ["ARCHIVED_HASH"] = preview.ExpectedHash }, marker: "UDP_FORWARD_READ");
                if (c.Plan.Text("Firewall.Mode") != "PreserveExisting") await c.Run("firewall-preflight.sh", FirewallParameters(c.Plan, true), marker: "FIREWALL_SCOPE_OK");
            }
        });
        if (action != "Check")
        {
            await c.TrackStep("udp-forward-backup", () => Arm(c, c.Plan.Text("Firewall.Mode") == "PreserveExisting" ? ["UdpForwarding"] : ["UdpForwarding", "Firewall"]));
            await c.TrackStep("udp-forward-apply", async () =>
            {
                if (action == "Remove") c.Plan.Remove("UdpForwarding"); else c.Plan["UdpForwarding"] = preview.Configuration.DeepClone(); c.Save();
                await c.Run("udp-forward-apply.sh", new() { ["ACTION"] = action, ["CONFIG_JSON"] = preview.Configuration.ToJsonString(), ["EXPECTED_HASH"] = preview.ExpectedHash }, true, 120, "UDP_FORWARD_APPLIED");
                await Firewall(c, true);
            });
        }
        await c.TrackStep("udp-forward-validation", async () =>
        {
            var observed = await Read();
            if (action == "Remove")
            {
                if (observed.Text("Hash") != "Absent") throw new OperationException("UDP 转发组件尚未完整移除，恢复本次范围。");
                c.State.Remove("UdpForwarding");
            }
            else
            {
                if (observed["Configuration"] == null || ArchiveStore.Fingerprint(observed["Configuration"]!) != ArchiveStore.Fingerprint(preview.Configuration)) throw new OperationException("实际 UDP 转发配置与审阅不符。");
                if (udpForwarding == null) throw new OperationException("UDP 应用验收适配器不可用，未提交变更。");
                var result = await udpForwarding.ValidateAsync(c.Plan, preview.Configuration, c.File("udp-forward-validation/" + c.Id), new InlineProgress<string>(m => c.Report("实际 UDP 转发验收", m)), c.Cancellation);
                UdpForwarding.RequireValidation(c.Plan, preview.Configuration, result);
                foreach (var rule in UdpForwarding.Rules(preview.Configuration).Where(r => r.Flag("Enabled") && r.Text("Validation.Type") == "Shadowsocks")) _ = UdpForwarding.ProxyNode(store, rule, c.Request.InstanceRelativePath);
                if ((await Read()).Text("Hash") != observed.Text("Hash")) throw new OperationException("UDP 验收期间配置发生变化，未提交。");
                c.State["UdpForwarding"] = new JsonObject { ["RemoteHash"] = observed.Text("Hash"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(preview.Configuration), ["TemplateCurrent"] = observed.Flag("TemplateCurrent", true), ["WorkerHash"] = observed["Files"]?["/etc/may-udp-forward/worker.py"]?.DeepClone(), ["Validation"] = result.DeepClone(), ["At"] = DateTimeOffset.UtcNow };
                if (!observed.Flag("TemplateCurrent", true)) { c.Warnings = true; c.Report("UDP 转发需要更新", "旧单元已按归档核对并保持原样，请重新审阅保存转发规则以应用当前启动依赖。"); }
            }
            await VerifyManagement(c); c.Save();
        });
        if (action != "Check") await c.TrackStep("udp-forward-commit", () => Commit(c));
    }
}
