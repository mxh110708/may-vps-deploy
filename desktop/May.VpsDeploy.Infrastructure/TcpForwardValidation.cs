using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class TcpForwardValidation(ArchiveStore store, ClientRouteDiagnostics diagnostics, X509Certificate2? certificateAuthority = null) : ITcpForwardValidation
{
    public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        try { return await Run(plan, configuration, privateDirectory, progress, cancellationToken); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new OperationException("TCP 转发验收超时，未提交本次变更。", code: "TcpForwardValidationTimeout"); }
        catch (AuthenticationException) { throw new OperationException("经 TCP 转发的 TLS 握手或证书校验失败，请核对目标服务及 TLS 域名。", code: "TcpForwardTlsFailed"); }
        catch (SocketException) { throw new OperationException("无法经 TCP 转发连接目标，请核对监听、来源白名单与目标服务。", code: "TcpForwardConnectFailed"); }
        catch (IOException) { throw new OperationException("经 TCP 转发的应用连接提前断开，未完成验收。", code: "TcpForwardStreamFailed"); }
    }
    private async Task<JsonObject> Run(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); budget.CancelAfter(TimeSpan.FromMinutes(3));
        var result = new JsonObject { ["Status"] = "Passed", ["At"] = DateTimeOffset.UtcNow, ["Items"] = new JsonArray() };
        foreach (var rule in TcpForwarding.Rules(configuration).Where(r => r.Flag("Enabled")))
        {
            var item = new JsonObject { ["Id"] = rule.Text("Id"), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ForwardedApplication", ["Checks"] = new JsonArray() };
            progress.Report("经转发验收：" + rule.Text("Name"));
            foreach (var host in TcpForwarding.ProbeAddresses(plan, rule))
            {
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(budget.Token); limit.CancelAfter(TimeSpan.FromSeconds(rule.Text("Validation.Type") == "Proxy" ? 75 : 12));
                var kind = rule.Text("Validation.Type");
                if (kind == "Proxy")
                {
                    var node = TcpForwarding.ProxyNode(store, rule, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy");
                    node["sing_box"]!["server"] = host; node["sing_box"]!["server_port"] = rule.Number("ListenPort");
                    var scheme = new JsonObject { ["Nodes"] = new JsonArray(node), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray("Forward validation") } };
                    var route = ClientTopology.DiagnosticRoute(scheme, node.Text("name"));
                    var check = await diagnostics.RunAsync(route, privateDirectory, progress, limit.Token);
                    if (check.Text("Status") != "Reachable") throw new OperationException("代理请求未通过当前 TCP 转发，未完成验收。", code: "TcpForwardProxyFailed");
                    item["Checks"]!.AsArray().Add(new JsonObject { ["Address"] = host, ["Type"] = kind, ["Status"] = "Passed", ["Result"] = check });
                }
                else
                {
                    using var client = new TcpClient(); await client.ConnectAsync(host, rule.Number("ListenPort"), limit.Token);
                    if (kind == "Tls")
                    {
                        using var tls = new SslStream(client.GetStream(), false);
                        var options = new SslClientAuthenticationOptions { TargetHost = rule.Text("Validation.ServerName") };
                        // A fixture may supply a process-local CA. Product construction
                        // uses the OS trust store; no UI setting disables validation.
                        if (certificateAuthority != null)
                        {
                            options.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                            options.CertificateChainPolicy.CustomTrustStore.Add(certificateAuthority);
                        }
                        await tls.AuthenticateAsClientAsync(options, limit.Token);
                        item["Checks"]!.AsArray().Add(new JsonObject { ["Address"] = host, ["Type"] = kind, ["Status"] = "Passed", ["CertificateValidated"] = true });
                    }
                    else if (kind == "Ssh")
                    {
                        var bytes = new byte[4096]; var count = 0; var found = false;
                        while (count < bytes.Length && !found)
                        {
                            var n = await client.GetStream().ReadAsync(bytes.AsMemory(count), limit.Token); if (n == 0) break; count += n;
                            var lines = Encoding.ASCII.GetString(bytes, 0, count).Split('\n');
                            found = lines.Take(lines.Length - 1).Any(line => line.StartsWith("SSH-2.0-", StringComparison.Ordinal) && line.Length is >= 9 and <= 256);
                        }
                        if (!found) throw new OperationException("经转发未收到完整 SSH 2.0 协议响应。", code: "TcpForwardSshFailed");
                        item["Checks"]!.AsArray().Add(new JsonObject { ["Address"] = host, ["Type"] = kind, ["Status"] = "Passed", ["Detail"] = "已收到转发后的 SSH 协议响应；未登录或验证主机公钥。" });
                    }
                    else throw new OperationException("未知的 TCP 转发验收方式。");
                }
            }
            result["Items"]!.AsArray().Add(item);
        }
        return result;
    }
}
