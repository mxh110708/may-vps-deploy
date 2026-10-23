using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task ConfigureTcpForwarding(Context c)
    {
        var preview = TcpForwarding.Prepare(store, c.Request); var action = c.Request.Options.Text("Action");
        async Task<JsonObject> Read()
        {
            var response = await c.Run("tcp-forward-read.sh", marker: "TCP_FORWARD_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "TCP_FORWARD_STATE"))!.AsObject();
        }
        await c.TrackStep("forward-preflight", async () =>
        {
            var audit = await c.Run("audit.sh");
            Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
            await VerifyManagement(c);
            var observed = await Read();
            if (observed.Text("Hash") != preview.ExpectedHash) throw new OperationException("转发实际配置、白名单或监听状态与归档不同，未写入服务器。", code: "TcpForwardRemoteDrift");
            if (action != "Check")
            {
                await c.Run("tcp-forward-read.sh", new() { ["CANDIDATE_JSON"] = preview.Configuration.ToJsonString() }, marker: "TCP_FORWARD_READ");
                if (c.Plan.Text("Firewall.Mode") != "PreserveExisting") await c.Run("firewall-preflight.sh", FirewallParameters(c.Plan, true), marker: "FIREWALL_SCOPE_OK");
            }
        });
        if (action != "Check")
        {
            await c.TrackStep("forward-backup", () => Arm(c, c.Plan.Text("Firewall.Mode") == "PreserveExisting" ? ["TcpForwarding"] : ["TcpForwarding", "Firewall"]));
            await c.TrackStep("forward-apply", async () =>
            {
                if (action == "Remove") c.Plan.Remove("TcpForwarding"); else c.Plan["TcpForwarding"] = preview.Configuration.DeepClone();
                c.Save();
                await c.Run("tcp-forward-apply.sh", new() { ["ACTION"] = action, ["CONFIG_JSON"] = preview.Configuration.ToJsonString(), ["EXPECTED_HASH"] = preview.ExpectedHash }, true, 120, "TCP_FORWARD_APPLIED");
                await Firewall(c, true);
            });
        }
        await c.TrackStep("forward-validation", async () =>
        {
            var observed = await Read();
            if (action == "Remove")
            {
                if (observed.Text("Hash") != "Absent") throw new OperationException("转发组件尚未完整移除，恢复本次范围。");
                c.State.Remove("TcpForwarding");
            }
            else
            {
                if (observed["Configuration"] == null || ArchiveStore.Fingerprint(observed["Configuration"]!) != ArchiveStore.Fingerprint(preview.Configuration)) throw new OperationException("实际转发配置与审阅结果不符。");
                if (tcpForwarding == null) throw new OperationException("实际转发验收适配器不可用，未提交变更。");
                var result = await tcpForwarding.ValidateAsync(c.Plan, preview.Configuration, c.File("tcp-forward-validation/" + c.Id), new InlineProgress<string>(m => c.Report("实际 TCP 转发验收", m)), c.Cancellation);
                TcpForwarding.RequireValidation(preview.Configuration, result);
                var after = await Read();
                if (after.Text("Hash") != observed.Text("Hash")) throw new OperationException("验收期间转发配置发生变化，未提交。");
                c.State["TcpForwarding"] = new JsonObject { ["RemoteHash"] = observed.Text("Hash"), ["Validation"] = result.DeepClone(), ["At"] = DateTimeOffset.UtcNow };
            }
            await VerifyManagement(c); c.Save();
        });
        if (action != "Check") await c.TrackStep("forward-commit", () => Commit(c));
    }
}
