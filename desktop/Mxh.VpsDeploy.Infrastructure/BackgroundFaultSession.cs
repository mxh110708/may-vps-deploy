using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Infrastructure;

// Enabled only by an explicit disposable test session. It closes that session's
// own SSH transport or exits its own app; it never changes machine-wide networking.
internal sealed class BackgroundFaultSession(BackgroundTestSession test, IRemoteSession inner) : IRemoteSession
{
    private static readonly string[] Assets = ["audit.sh", "ssh-transition.sh", "nftables-apply.sh", "xray-install.sh", "deployment-snapshot-delete.sh", "network-apply.sh", "kernel-prepare.sh", "kernel-boot.sh", "kernel-confirm.sh", "kernel-rollback.sh"];
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken cancellationToken) => inner.RunAsync(command, timeout, cancellationToken);
    public Task<byte[]> ReadFileAsync(string path, CancellationToken cancellationToken) => inner.ReadFileAsync(path, cancellationToken);
    public Task DownloadAsync(string path, string destination, CancellationToken cancellationToken) => inner.DownloadAsync(path, destination, cancellationToken);
    public ValueTask DisposeAsync() => inner.DisposeAsync();

    public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken cancellationToken)
    {
        var first = payload.Split('\n', 2)[0];
        var asset = first.StartsWith("# MXH asset: ", StringComparison.Ordinal) ? first[13..].Trim() : "ssh-verification";
        var faultFile = SafePath.Resolve(test.Root, "test-secrets/transport-fault.private.json");
        JsonObject? fault = File.Exists(faultFile) ? ReadFault(faultFile) : null;
        var matches = fault != null && fault.Text("Asset") == asset;
        var consumed = fault == null ? "" : test.Artifact("fault-" + fault.Text("Id") + ".private.json");
        matches &= consumed != "" && !File.Exists(consumed);
        if (matches) ArchiveStore.WriteJson(consumed, new JsonObject { ["asset"] = asset, ["action"] = fault!.Text("Action"), ["at"] = DateTimeOffset.UtcNow.ToString("o") });
        if (matches && fault!.Text("Action") == "DisconnectBefore") { Journal(asset, mutating, "fault_before_request", true); await Interrupt(false, false); }
        Journal(asset, mutating, "request", matches);
        var result = await inner.RunScriptAsync(payload, timeout, mutating, cancellationToken);
        Journal(asset, mutating, "remote_returned", matches);
        if (matches && result.ExitCode == 0 && fault!.Text("Action") is "DisconnectAfter" or "ExitAfter")
            await Interrupt(fault.Text("Action") == "ExitAfter");
        return result;
    }

    private static JsonObject ReadFault(string file)
    {
        SafePath.CheckLinks(file);
        if (new FileInfo(file).Length > 4096) throw new OperationException("后台中断测试参数过大。");
        var fault = ArchiveStore.ReadJson(file);
        if (fault.Number("SchemaVersion") != 1 || !Guid.TryParseExact(fault.Text("Id"), "N", out _) || !Assets.Contains(fault.Text("Asset")) ||
            fault.Text("Action") is not ("DisconnectBefore" or "DisconnectAfter" or "ExitAfter")) throw new OperationException("后台中断测试参数无效。");
        return fault;
    }
    private void Journal(string asset, bool mutating, string phase, bool injected)
    {
        var file = test.Artifact("transport-journal.private.jsonl"); SafePath.CheckLinks(file);
        var entry = new JsonObject { ["at"] = DateTimeOffset.UtcNow.ToString("o"), ["asset"] = asset, ["mutating"] = mutating, ["phase"] = phase, ["fault"] = injected };
        File.AppendAllText(file, entry.ToJsonString() + "\n");
    }
    private async Task Interrupt(bool exit, bool needsRecovery = true)
    {
        await inner.DisposeAsync();
        if (exit) Environment.Exit(70);
        throw new OperationException(needsRecovery ? "测试会话的 SSH 连接已中断；远端写入结果需要核对。" : "测试会话在请求发送前已中断，远端命令尚未执行。", needsRecovery, "SshDisconnected");
    }
}
