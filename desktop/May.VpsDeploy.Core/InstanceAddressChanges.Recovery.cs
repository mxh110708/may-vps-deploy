using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static partial class InstanceAddressChanges
{
    private static void ValidateRecovery(ArchiveStore store, OperationRequest request, JsonObject record)
    {
        void Require(bool condition) { if (!condition) throw new OperationException("换址恢复记录身份、版本或资源范围不受支持，未写入。", true, "AddressRecoveryScope"); }
        var id = request.Options.Text("Id");
        Require(record.Text("Id") == id && record.Text("Phase") is "Preparing" or "Applied" or "Validated" or "NeedsRecovery" or "Restoring");
        Require(record["Document"] is JsonObject && record["LocalFiles"] is JsonObject && record["Attempted"] is JsonArray);
        var document = record["Document"]!.AsObject();
        Require(document.Number("Version") == 1 && document.Text("Instance") == request.InstanceRelativePath && Regex.IsMatch(document.Text("ProgramSha256"), "^[a-f0-9]{64}$"));
        Require(document["Hosts"] is JsonArray { Count: > 0 and <= 128 } && document["Files"] is JsonArray && document["Addresses"] is JsonObject { Count: > 0 and <= 2 });
        Require(document["Hosts"]!.AsArray().All(h => h is JsonObject) && document["Files"]!.AsArray().All(f => f is JsonObject));
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ssh-hosts.dotnet.json" }; var participants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var host in document["Hosts"]!.AsArray().OfType<JsonObject>())
        {
            var relative = host.Text("Instance"); _ = store.Paths.Instance(relative);
            Require(relative.Replace('\\', '/') == relative && participants.Add(relative) && host["Before"] is JsonObject && host["After"] is JsonObject && host["State"] is JsonObject && host["Resources"] is JsonArray);
            foreach (var version in new[] { "Before", "After" }) Require(relative == host.Text(version + ".Provider") + "/" + host.Text(version + ".Instance") + "/May-VPS-Deploy");
            Require(Regex.IsMatch(host.Text("Pin"), @"^SHA256:[A-Za-z0-9+/]{43}$"));
            foreach (var kind in new[] { "Plan", "State", "Secrets" }) Require(Regex.IsMatch(host.Text("Hashes." + kind), "^[a-f0-9]{64}$"));
            foreach (var file in new[] { "deployment-plan.json", "deployment-state.json" }) allowed.Add("instances/" + relative + "/" + file);
            foreach (var (_, file) in ProtocolFiles) allowed.Add("instances/" + relative + "/server-configs/" + file);
            Require(host["Resources"]!.AsArray().All(r => r is JsonObject && new[] { "Firewall", "RealityEntry", "AnyTlsEntry", "ShadowsocksLanding", "TcpForwarding", "UdpForwarding", "WireGuardTunnel", "WireGuardTunnel2", "Inbounds" }.Contains(r.Text("Kind"))));
        }
        Require(participants.Contains(request.InstanceRelativePath) && participants.Count == document["Hosts"]!.AsArray().Count);
        Require(record["Attempted"]!.AsArray().All(v => v != null && participants.Contains(v.ToString())));
        foreach (var file in document["Files"]!.AsArray().OfType<JsonObject>())
        {
            var path = file.Text("Path");
            Require(allowed.Contains(path) || Regex.IsMatch(path, @"^(client-schemes|client-node-groups)/[a-f0-9]{32}\.dotnet\.private\.json$|^(tcp-chains|wireguard-tunnels)/[a-f0-9]{32}\.json$"));
            Require(file["Before"] is JsonObject && file["After"] is JsonObject && Regex.IsMatch(file.Text("Hash"), "^[a-f0-9]{64}$")); allowed.Add(path);
        }
        foreach (var (path, value) in record["LocalFiles"]!.AsObject())
        {
            Require(allowed.Contains(path) && value is JsonObject); _ = SafePath.Resolve(store.Paths.Private, path);
            var item = value!.AsObject(); var original = item["Before"] == null ? null : Convert.FromBase64String(item.Text("Before"));
            Require(item.Text("BeforeHash") == (original == null ? "Absent" : ArchiveStore.Digest(original)));
            Require(item.Text("CurrentHash") == "Absent" || Regex.IsMatch(item.Text("CurrentHash"), "^[a-f0-9]{64}$"));
        }
    }
}
