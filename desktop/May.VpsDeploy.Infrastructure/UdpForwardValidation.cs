using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class UdpForwardValidation(ArchiveStore? store = null, IValidationAssets? assets = null, IExternalToolRunner? tools = null) : IUdpForwardValidation
{
    public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); budget.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            var result = new JsonObject { ["Status"] = "Passed", ["At"] = DateTimeOffset.UtcNow, ["Items"] = new JsonArray() };
            foreach (var rule in UdpForwarding.Rules(UdpForwarding.Normalize(configuration)).Where(r => r.Flag("Enabled")))
            {
                progress.Report("UDP 往返验收：" + rule.Text("Name"));
                var item = new JsonObject { ["Id"] = rule.Text("Id"), ["From"] = "Controller", ["Scope"] = "ForwardedDatagramApplication", ["Status"] = "Passed", ["Checks"] = new JsonArray() };
                foreach (var address in TcpForwarding.ProbeAddresses(plan, rule))
                {
                    var kind = rule.Text("Validation.Type");
                    if (kind == "Shadowsocks")
                    {
                        if (store == null || assets == null || tools == null) throw new OperationException("UDP 代理验收适配器不可用，未提交变更。");
                        var changingInstance = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy";
                        var node = UdpForwarding.ProxyNode(store, rule, changingInstance);
                        try
                        {
                            var evidence = await new UdpProxyProbe(assets, tools).RunAsync(node, rule["Validation"]!.AsObject(), address, rule.Number("ListenPort"), privateDirectory, budget.Token);
                            _ = UdpForwarding.ProxyNode(store, rule, changingInstance);
                            evidence["Address"] = address; evidence["Type"] = kind; evidence["Status"] = "Passed"; evidence["NodeFingerprint"] = rule.Text("Validation.NodeFingerprint");
                            item["Checks"]!.AsArray().Add(evidence);
                        }
                        finally { node.Clear(); }
                        continue;
                    }
                    var request = kind == "Dns" ? UdpDnsProbe.Query(rule.Text("Validation.QueryName"), rule.Text("Validation.QueryType")) : RandomNumberGenerator.GetBytes(32);
                    using var client = new UdpClient(IPAddress.Parse(address).AddressFamily); client.Connect(IPAddress.Parse(address), rule.Number("ListenPort"));
                    var passed = false;
                    for (var attempt = 0; attempt < 3 && !passed; attempt++)
                    {
                        using var responseBudget = CancellationTokenSource.CreateLinkedTokenSource(budget.Token); responseBudget.CancelAfter(TimeSpan.FromSeconds(2));
                        try
                        {
                            await client.SendAsync(request.AsMemory(), responseBudget.Token);
                            for (var received = 0; received < 16 && !passed; received++)
                            {
                                var response = (await client.ReceiveAsync(responseBudget.Token)).Buffer;
                                passed = kind == "Dns" ? UdpDnsProbe.Matches(request, response) : response.AsSpan().SequenceEqual(request);
                            }
                        }
                        catch (OperationCanceledException) when (!budget.IsCancellationRequested) { }
                    }
                    if (!passed) throw new OperationException("未收到经 UDP 转发的匹配 DNS 回答或原样回显；请核对目标服务、UDP 放行和来源白名单。", code: "UdpForwardProbeFailed");
                    item["Checks"]!.AsArray().Add(new JsonObject { ["Address"] = address, ["Type"] = kind, ["Status"] = "Passed", ["ResponseMatched"] = true });
                }
                result["Items"]!.AsArray().Add(item);
            }
            return result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new OperationException("UDP 转发应用验收超时，未提交变更。", code: "UdpForwardValidationTimeout"); }
        catch (SocketException) { throw new OperationException("UDP 往返连接失败，请核对监听、目标服务及防火墙；未提交变更。", code: "UdpForwardConnectFailed"); }
    }
}

public static class UdpDnsProbe
{
    public static byte[] Query(string name, string type)
    {
        UdpForwarding.ValidateQueryName(name);
        if (type is not ("A" or "AAAA")) throw new OperationException("UDP DNS 验收仅支持 A 或 AAAA 查询。");
        using var stream = new MemoryStream(); var header = new byte[12]; RandomNumberGenerator.Fill(header.AsSpan(0, 2)); header[2] = 1; header[5] = 1; stream.Write(header);
        foreach (var label in name.ToLowerInvariant().Split('.')) { var bytes = Encoding.ASCII.GetBytes(label); stream.WriteByte((byte)bytes.Length); stream.Write(bytes); }
        stream.WriteByte(0); stream.Write([0, type == "A" ? (byte)1 : (byte)28, 0, 1]); return stream.ToArray();
    }
    public static bool Matches(byte[] query, byte[] response)
    {
        if (query.Length < 17 || response.Length < query.Length || response.Length > 4096 || !query.AsSpan(0, 2).SequenceEqual(response.AsSpan(0, 2))) return false;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
        var answers = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6));
        if ((flags & 0xfa0f) != 0x8000 || response[4] != 0 || response[5] != 1 || answers is < 1 or > 64 || !query.AsSpan(12).SequenceEqual(response.AsSpan(12, query.Length - 12))) return false;
        var type = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(query.Length - 4)); var offset = query.Length;
        for (var i = 0; i < answers; i++)
        {
            if (!SkipName(response, ref offset) || offset + 10 > response.Length) return false;
            var recordType = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset));
            var recordClass = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 8)); offset += 10;
            if (offset + length > response.Length) return false;
            if (recordClass == 1 && recordType == type && length == (type == 1 ? 4 : 16)) return true;
            offset += length;
        }
        return false;
    }
    private static bool SkipName(byte[] message, ref int offset)
    {
        for (var count = 0; count < 128 && offset < message.Length; count++)
        {
            var length = message[offset++]; if (length == 0) return true;
            if ((length & 0xc0) == 0xc0) return offset < message.Length && (((length & 0x3f) << 8) | message[offset++]) < message.Length;
            if (length > 63 || offset + length > message.Length) return false;
            offset += length;
        }
        return false;
    }
}
