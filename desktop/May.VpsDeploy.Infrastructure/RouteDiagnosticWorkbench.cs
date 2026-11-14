using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public interface IRouteSegmentProbe
{
    Task<JsonObject> ProbeAsync(RouteDiagnosticSegment segment, CancellationToken cancellationToken);
}

public sealed class RouteSegmentProbe(ArchiveStore store, IRemoteSessionFactory connections, IUserInteraction interaction) : IRouteSegmentProbe
{
    public async Task<JsonObject> ProbeAsync(RouteDiagnosticSegment segment, CancellationToken cancellationToken)
    {
        if (segment.Component is not ("TcpForwarding" or "UdpForwarding") || segment.Transport is not ("TCP" or "UDP") || segment.Port is < 1 or > 65535 || !System.Net.IPAddress.TryParse(segment.Address, out var target) || target.IsIPv4MappedToIPv6 || segment.Address.Contains('%') || !RouteDiagnostics.Digest(segment.ComponentHash)) throw new OperationException("分段探测参数无效。");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token; var plan = TcpChains.Plan(store, segment.Instance);
        var directory = store.Paths.Instance(segment.Instance); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        if (InstanceLifecycle.Read(store, segment.Instance, plan).NeedsRecovery || state.Text(segment.Component + ".RemoteHash") != segment.ComponentHash)
            throw new OperationException("分段归档正在恢复或已变化，未连接远端。");
        var key = SafePath.Resolve(directory, "ssh/" + AppPaths.Segment(plan.Text("SshKey.ManagedFileName", "id_vps_management")));
        if (!File.Exists(key)) key = plan.Text("SshKey.SourcePrivateKeyPath", plan.Text("Server.BootstrapKeyPath"));
        if (key == "" || !File.Exists(key)) throw new OperationException("分段诊断需要已配置的 SSH 管理密钥；请先完善实例管理连接。", code: "DiagnosticManagement");
        var endpoint = new SshEndpoint(plan.Text("Server.IPv4"), state.Number("CurrentManagementPort", plan.Number("Ports.SshPrimary")), "root", key);
        IRemoteSession session;
        try { session = await connections.OpenAsync(endpoint, interaction, ct); }
        catch (KeyPassphraseRequiredException)
        {
            var passphrase = await interaction.SecretAsync(plan.Text("NodeName") + " · SSH 私钥口令", ct) ?? throw new OperationException("诊断凭据输入已取消。", code: "DiagnosticCancelled");
            session = await connections.OpenAsync(endpoint with { KeyPassphrase = passphrase }, interaction, ct);
        }
        await using (session)
        {
            var assets = new RemoteAssets(store.Paths); var udp = segment.Component == "UdpForwarding";
            var prefix = udp ? "UDP_FORWARD" : "TCP_FORWARD";
            var read = await session.RunScriptAsync(assets.Payload(udp ? "udp-forward-read.sh" : "tcp-forward-read.sh", new Dictionary<string, string>()), TimeSpan.FromSeconds(10), false, ct);
            if (read.ExitCode != 0) throw new OperationException("未取得分段转发配置，未探测此段。", code: "DiagnosticRemoteConfiguration");
            var observed = Parse(read.Output, prefix + "_STATE");
            if (observed.Text("Hash") != segment.ComponentHash) throw new OperationException("分段远端配置与归档不同，未探测此段。", code: "DiagnosticSegmentDrift");
            var result = await session.RunScriptAsync(assets.Payload("tcp-chain-probe.sh", new Dictionary<string, string> { ["ADDRESS"] = segment.Address, ["PORT"] = segment.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), ["TRANSPORT"] = segment.Transport }), TimeSpan.FromSeconds(10), false, ct);
            if (result.ExitCode != 0) throw new OperationException("此段连接未通过；需要结合整条业务路径核对。", code: "DiagnosticSegmentConnect");
            var probe = Parse(result.Output, "TCP_CHAIN_PROBE");
            if (probe.Text("Address") != segment.Address || probe.Number("Port") != segment.Port || probe.Text("Scope") != (segment.Transport == "UDP" ? "UdpRouteOnly" : "TcpConnectOnly") ||
                probe.Text("Status") != (segment.Transport == "UDP" ? "RouteAvailable" : "Connected") || probe.Long("Milliseconds", -1) is < 0 or > 10000)
                throw new OperationException("分段返回证据不完整，未作为成功记录。");
            return probe;
        }
    }
    private static JsonObject Parse(string output, string marker)
    {
        try { return JsonNode.Parse(RemoteAssets.Marker(output, marker))?.AsObject() ?? throw new FormatException(); }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or FormatException)
        { throw new OperationException("远端诊断返回格式无效，未作为成功记录。"); }
    }
}

public static class DiagnosticNetworkContext
{
    // Store only a digest. A changed gateway/interface/DNS/source address starts
    // a separate quality series, with no adapter names or local addresses saved.
    public static string Capture()
    {
        var rows = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n => { var p = n.GetIPProperties(); return n.Id + ":" + string.Join(',', p.UnicastAddresses.Select(a => a.Address.ToString()).Order(StringComparer.Ordinal)) + ":" + string.Join(',', p.GatewayAddresses.Select(a => a.Address.ToString()).Order(StringComparer.Ordinal)) + ":" + string.Join(',', p.DnsAddresses.Select(a => a.ToString()).Order(StringComparer.Ordinal)); }).Order(StringComparer.Ordinal);
        return ArchiveStore.Fingerprint(new JsonObject { ["Machine"] = Environment.MachineName, ["Networks"] = string.Join('\n', rows) });
    }
}

public sealed class RouteDiagnosticWorkbench(ArchiveStore store, IClientRouteDiagnostics diagnostics, IRouteSegmentProbe? segments = null, IMonitorReadProbe? monitor = null, Func<string>? networkContext = null)
{
    public async Task<JsonObject> RunAsync(RouteDiagnosticPlan plan, bool probeSegments, bool readMonitor, IProgress<string> progress, CancellationToken cancellationToken)
    {
        var network = networkContext ?? DiagnosticNetworkContext.Capture;
        var context = network(); if (!RouteDiagnostics.Digest(context)) throw new OperationException("无法确定观测网络，未开始诊断。");
        RouteDiagnostics.VerifySources(store, plan.Route);
        var report = new JsonObject { ["Schema"] = RouteDiagnostics.Schema, ["Id"] = Guid.NewGuid().ToString("N"), ["At"] = DateTimeOffset.UtcNow.ToString("O"),
            ["SourceFingerprint"] = plan.SourceFingerprint, ["EnvironmentFingerprint"] = context, ["Profile"] = "", ["Path"] = plan.Route.Label,
            ["EntryId"] = plan.Route.Entry.Text("Id"), ["LandingId"] = plan.Route.Landing?.Text("Id") ?? "", ["Status"] = "Incomplete", ["FailureStage"] = "",
            ["Protocol"] = ClientStreamTransports.Label(plan.Route.Entry), ["Stages"] = new JsonArray(), ["Segments"] = new JsonArray(), ["Monitor"] = new JsonArray(),
            ["Scope"] = "主动短连接；分段仅连接或路由，协议与 HTTPS 出口合并验收。耗时含握手及网站响应，不是 ping／远端纯 RTT；不测吞吐，不代表当前客户端选择。" };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(150)); var ct = deadline.Token;
        var clock = Stopwatch.StartNew(); var activeStage = "Preparation";
        try
        {
            foreach (var segment in plan.Segments)
            {
                ct.ThrowIfCancellationRequested(); activeStage = segment.Id; progress.Report(segment.Label);
                var row = new JsonObject { ["Id"] = segment.Id, ["Label"] = segment.Label, ["FromInstance"] = segment.Instance, ["Transport"] = segment.Transport,
                    ["Status"] = "NotMeasured", ["Kind"] = "NotMeasured", ["Detail"] = "未选择远端分段检查；没有推算远端延迟。" };
                report["Segments"]!.AsArray().Add(row);
                if (!probeSegments || segments == null) continue;
                try
                {
                    var probe = await segments.ProbeAsync(segment, ct);
                    row["Status"] = probe.Text("Status"); row["Kind"] = segment.Transport == "UDP" ? "RouteOnly" : "Measured";
                    if (segment.Transport == "TCP") row["Milliseconds"] = probe.Long("Milliseconds");
                    row["Detail"] = segment.Transport == "UDP" ? "仅内核可选路由；无 UDP 往返、协议鉴权或延迟证明。" : "仅此来源的 TCP connect；不是纯 RTT，也未独立核验代理鉴权。";
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { row["Status"] = "Cancelled"; throw; }
                catch (OperationException e) when (e.Code == "DiagnosticCancelled") { row["Status"] = "Cancelled"; throw; }
                catch (Exception e) when (e is OperationException or IOException or System.Net.Sockets.SocketException or OperationCanceledException)
                {
                    row["Status"] = "Failed"; row["Kind"] = "Measured";
                    row["Detail"] = e is OperationException safe ? safe.Code switch
                    {
                        "DiagnosticSegmentConnect" => "已核对转发配置，此来源到目标的连接未通过；不据此跳过整链协议检查。",
                        "DiagnosticSegmentDrift" or "DiagnosticRemoteConfiguration" => "远端转发配置读取或摘要核对未通过，未连接此段目标。",
                        "DiagnosticManagement" => "SSH 管理密钥未就绪，未连接此段目标。",
                        _ => "分段管理连接或返回证据未通过；尚不能归因到目标网络。"
                    } : "分段管理连接未完成；尚不能归因到目标网络。";
                }
            }
            activeStage = "Core";
            var result = await diagnostics.RunAsync(plan.Route with { PreservePartialOnCancel = true }, store.Paths.Resolve("private/client-diagnostics"), progress, ct);
            report["Profile"] = result.Text("Profile");
            foreach (var stage in (result["Stages"] as JsonArray ?? []).OfType<JsonObject>().Take(24))
            {
                var id = stage.Text("Id"); var status = stage.Text("Status");
                var row = new JsonObject { ["Id"] = id, ["Label"] = RouteDiagnostics.StageLabel(id), ["Status"] = status, ["Kind"] = status == "NotMeasured" ? "NotMeasured" : "Measured" };
                if (stage["Milliseconds"] != null) row["Milliseconds"] = stage.Long("Milliseconds");
                // Raw core/SSH errors and user configuration are never archived.
                if (status == "Failed") row["Detail"] = "此合并阶段未通过；可能涉及路径、协议身份、目标或出口核对，不能单凭阶段确定根因。";
                if (status == "NotMeasured") row["Detail"] = "没有独立实测；不由其他阶段相减估算。";
                report["Stages"]!.AsArray().Add(row);
            }
            foreach (var key in new[] { "EntryEgress", "ChainEgress" })
                if (result[key] is JsonObject exit) report[key] = new JsonObject { ["Address"] = exit.Text("Address"), ["Family"] = exit.Text("Family"), ["Verified"] = exit.Flag("Verified") };
            report["FailureStage"] = report["Stages"]!.AsArray().FirstOrDefault(s => s!.Text("Status") is "Failed" or "Cancelled")?.Text("Id") ?? "";
            report["Status"] = result.Text("Status") == "Reachable" ? report["Segments"]!.AsArray().Any(s => s!.Text("Status") == "Failed") ? "Degraded" : "Reachable" : result.Text("Status", "Incomplete");
            if (ct.IsCancellationRequested) report["Status"] = cancellationToken.IsCancellationRequested ? "Cancelled" : "TimedOut";
            if (!ct.IsCancellationRequested && readMonitor && plan.Instances.Count > 0)
            {
                activeStage = "Monitor"; progress.Report("读取 May Monitor 旁证（不决定业务路径成败）");
                var archive = new MonitorReadArchive(store); MonitorReadConnection? connection = null;
                try
                {
                    connection = archive.Load();
                    var snapshot = connection != null && monitor != null ? await monitor.FetchAsync(connection, ct) : null;
                    if (connection != null && archive.Load()?.Identity != connection.Identity) throw new OperationException("监测连接在读取期间变化。");
                    report["Monitor"] = RouteDiagnostics.MonitorEvidence(plan, connection, snapshot, DateTimeOffset.UtcNow, false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception e) when (e is OperationException or IOException or System.Net.Http.HttpRequestException)
                { report["Monitor"] = RouteDiagnostics.MonitorEvidence(plan, connection, null, DateTimeOffset.UtcNow, true); }
            }
        }
        catch (OperationCanceledException)
        { report["Status"] = cancellationToken.IsCancellationRequested ? "Cancelled" : "TimedOut"; report["FailureStage"] = activeStage; }
        catch (OperationException e) when (e.Code == "DiagnosticCancelled")
        { report["Status"] = "Cancelled"; report["FailureStage"] = activeStage; }
        catch (Exception e) when (e is OperationException or IOException or System.Net.Sockets.SocketException or System.Net.Http.HttpRequestException)
        { report["Status"] = "Failed"; report["FailureStage"] = activeStage; }
        finally { report["ElapsedMilliseconds"] = clock.ElapsedMilliseconds; }
        try
        {
            RouteDiagnostics.VerifySources(store, plan.Route);
            if (network() != context) { report["Status"] = "SourceChanged"; report["FailureStage"] = "NetworkContext"; }
            foreach (var s in plan.Segments)
            {
                var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(s.Instance), "deployment-state.json"));
                if (state.Text(s.Component + ".RemoteHash") != s.ComponentHash) throw new OperationException("分段来源变化。");
            }
        }
        catch (Exception e) when (e is OperationException or IOException or UnauthorizedAccessException)
        { report["Status"] = "SourceChanged"; report["FailureStage"] = "Source"; }
        return report;
    }
}
