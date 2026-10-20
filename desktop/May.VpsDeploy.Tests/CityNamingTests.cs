using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void CityNamingExperience(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths);
        var regions = scheme["Layout"]!.Strings("region_groups");
        Check(regions.Contains("US-West-LA Entry") && regions.Contains("US-West-SF Entry") && !regions.Contains("US-West Entry"), "new layout lost city or metro groups");
        var form = new JsonObject { ["Provider"] = "Example", ["Instance"] = "Landing", ["IPv4"] = "192.0.2.40", ["IPv6"] = "2001:db8::40", ["Role"] = "ShadowsocksLanding", ["TrustedEntries"] = "192.0.2.41", ["SecondaryIpv6Enabled"] = true, ["SecondaryIpv6Address"] = "2001:db8:1::40" };
        var plan = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        Check(plan.Text("Shadowsocks.ClientTransitTag") == "US-West-LA Entry", "landing default still uses ambiguous region");
        var secrets = new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = "synthetic-server", ["PrimaryUserKey"] = "synthetic-v4", ["SecondaryUserKey"] = "synthetic-v6" } };
        var before = ClientProfiles.Nodes(plan, secrets).ToArray();
        Check(before.Length == 4 && before.All(n => n.Name.Contains(".IPv") && n.Name.EndsWith("-" + n.Family)), "existing unnamed landing changed its name");
        form["LandingPrimaryName"] = "US-West-LA Exit A IPv4";
        form["LandingSecondaryName"] = "US-West-SF Exit A ATT IPv6";
        plan = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        var after = ClientProfiles.Nodes(plan, secrets).ToArray();
        Check(after.Length == 4 && after.Select(n => n.Name).Distinct().Count() == 4, "egress city and connection families collided");
        Check(after.Single(n => n.Family == "IPv4" && n.EgressFamily == "IPv4").Name == "US-West-LA Exit A IPv4", "native egress city changed");
        Check(after.Single(n => n.Family == "IPv4" && n.EgressFamily == "IPv6").Name == "US-West-SF Exit A ATT IPv6", "leased egress inferred from native city");
        Check(after.Where(n => n.Family == "IPv6").All(n => n.Name.EndsWith("-Via-IPv6")), "IPv6 connection confused with egress family");
        foreach (var node in after)
        {
            var old = before.Single(n => n.Family == node.Family && n.EgressFamily == node.EgressFamily);
            Check(ManagedNodeSources.Fingerprint(old) == ManagedNodeSources.Fingerprint(node), "name-only change modified connection or credentials");
            Check(node.Clash.Text("name") == node.Name && node.SingBox.Text("tag") == node.Name, "client formats disagree on city name");
            var origin = ManagedNodeSources.Origin(f.Relative(plan), old);
            Check(ManagedNodeSources.Resolve(origin, plan, secrets)?.Name == node.Name, "managed source lost identity after rename");
        }
        var review = DeploymentReview.Sections(plan, OperationKind.Deploy).SelectMany(section => section.Items).ToArray();
        Check(review.Any(item => item.Value == "US-West-SF Exit A ATT IPv6") && review.Any(item => item.Value == "US-West-LA Entry"), "review hides independent egress name or transit group");
        foreach (var region in regions)
        {
            scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = region + " fixture", ["kind"] = "entry", ["region_group"] = region, ["clash"] = new JsonObject { ["name"] = region + " fixture" }, ["sing_box"] = new JsonObject { ["tag"] = region + " fixture" } });
        }
        var specification = ClientSchemes.Specification(scheme);
        Check(specification["groups"]!.AsArray().Any(g => g.Text("name") == "US-West-SF Entry"), "SF entry cannot generate a selector");
        // A saved custom/legacy region is data; no location inference may silently rename it.
        var legacy = ClientSchemes.New(f.Paths);
        legacy["Layout"]!["region_groups"] = new JsonArray("US-West Entry");
        legacy["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = "old", ["kind"] = "entry", ["region_group"] = "US-West Entry", ["clash"] = new JsonObject { ["name"] = "old" }, ["sing_box"] = new JsonObject { ["tag"] = "old" } });
        Check(!ClientSchemes.UpgradeLayout(legacy) && ClientSchemes.Specification(legacy)["groups"]![0]!.Text("name") == "US-West Entry", "saved custom region renamed without city evidence");
        form["LandingSecondaryName"] = form["LandingPrimaryName"]!.DeepClone();
        Refuses(() => DeploymentPlans.Create(form, f.Versions, f.Paths, false), "duplicate egress labels accepted");
        form["LandingSecondaryName"] = "bad\nname";
        Refuses(() => DeploymentPlans.Create(form, f.Versions, f.Paths, false), "control character accepted in landing name");
        form["LandingSecondaryName"] = "Custom private egress"; form["TransitGroup"] = "My custom entry";
        var custom = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        Check(custom.Text("Shadowsocks.ClientTransitTag") == "My custom entry" && DeploymentNaming.LandingName(custom, "IPv6") == "Custom private egress", "custom names overwritten by regional defaults");
    }
}
