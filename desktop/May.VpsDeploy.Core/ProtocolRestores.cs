using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class ProtocolRestores
{
    public static bool Compatible(JsonObject record, JsonObject plan) => record.Strings("Components").Contains("Protocols")
        && record["OldPlan"] is JsonObject && record["OldState"] is JsonObject
        && record.Text("SshPorts") == plan.Text("Ports.SshPrimary") + "," + plan.Text("Ports.SshRescue")
        && Regex.IsMatch(record.Text("RemoteBackup"), @"^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$")
        && Regex.IsMatch(record.Text("BackupSha256"), "^[a-f0-9]{64}$")
        && Regex.IsMatch(record.Text("SecretsRelativePath"), @"^maintenance-backups/[a-f0-9]{32}/secrets\.dotnet\.private\.json$");
}
