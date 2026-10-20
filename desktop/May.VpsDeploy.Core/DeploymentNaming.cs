using System.Text.RegularExpressions;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed class DeploymentNaming
{
    // Names describe egress location. A native IPv4 and a leased IPv6 may be in different cities.
    public static void ValidateLandingNames(JsonObject plan)
    {
        var primary = plan.Text("Shadowsocks.ClientPrimaryName");
        var secondary = plan.Text("Shadowsocks.ClientSecondaryName");
        foreach (var value in new[] { primary, secondary })
            if (value.Length > 110 || value.Any(char.IsControl) || value.Length > 0 && value.Trim() != value)
                throw new OperationException("落地节点名称应为不超过 110 个可打印字符，两端不能包含空格。");
        if (primary != "" && primary == secondary && plan.Flag("Shadowsocks.SecondaryIpv6Enabled"))
            throw new OperationException("IPv4 与 IPv6 出口节点不能使用相同名称。");
    }
    public static string LandingName(JsonObject plan, string egressFamily, string connectionFamily = "IPv4")
    {
        ValidateLandingNames(plan);
        var name = plan.Text(egressFamily == "IPv6" ? "Shadowsocks.ClientSecondaryName" : "Shadowsocks.ClientPrimaryName");
        if (name == "") return plan.Text("NodeName") + "." + egressFamily + "-Exit" + (plan.Text("Server.IPv6") == "" ? "" : "-" + connectionFamily);
        // Keep the familiar name for IPv4 transport; distinguish an additional IPv6 listener.
        return name + (connectionFamily == "IPv6" ? "-Via-IPv6" : "");
    }
    private string previousSuggestion = "";
    public static string Suggest(string provider, string instance)
    {
        var value = Regex.Replace(string.Join("-", new[] { provider.Trim(), instance.Trim() }.Where(s => s.Length > 0)), @"\s+", "-");
        return value.Length <= 120 ? value : value[..120].TrimEnd('-');
    }
    public string Update(string provider, string instance, string current)
    {
        var suggestion = Suggest(provider, instance);
        var result = current.Length == 0 || current == previousSuggestion ? suggestion : current;
        previousSuggestion = suggestion;
        return result;
    }
}
