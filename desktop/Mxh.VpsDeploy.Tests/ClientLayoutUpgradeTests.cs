using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void ClientLayoutUpgradeExperience(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths);
        scheme["Layout"]!.AsObject().Remove("business_policy");
        var groups = scheme["Layout"]!["business_groups"]!.AsArray();
        var google = groups.First(g => g.Text("name") == "Google Services")!; groups.Remove(google);
        groups.First(g => g.Text("name") == "AI Services")!["default"] = "Europe Entry";
        scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
        var nodes = scheme["Nodes"]!.DeepClone();
        Check(ClientSchemes.UpgradeLayout(scheme) && scheme["Candidate"] == null, "legacy scheme retained a validated candidate after layout upgrade");
        var names = groups.Select(g => g.Text("name")).ToArray();
        Check(names.Count(n => n == "Google Services") == 1 && Array.IndexOf(names, "Academic Research") + 1 == Array.IndexOf(names, "Google Services") && Array.IndexOf(names, "Google Services") + 1 == Array.IndexOf(names, "Microsoft Services"), "Google scheme order wrong");
        Check(groups.First(g => g.Text("name") == "AI Services").Text("default") == "Europe Entry" && ArchiveStore.Fingerprint(nodes) == ArchiveStore.Fingerprint(scheme["Nodes"]!), "layout upgrade reset user choices or nodes");
        scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
        Check(!ClientSchemes.UpgradeLayout(scheme) && scheme["Candidate"] != null, "current scheme repeatedly invalidated");
        scheme["Layout"]!.AsObject().Remove("business_policy"); groups.First(g => g.Text("name") == "Google Services")!["default"] = "Europe Entry";
        Check(ClientSchemes.UpgradeLayout(scheme) && groups.First(g => g.Text("name") == "Google Services").Text("default") == "Europe Entry", "existing Google choice discarded");
        scheme["Layout"]!["business_policy"] = "FuturePolicy.v2";
        Refuses(() => ClientSchemes.UpgradeLayout(scheme), "future business policy downgraded silently");
        scheme["Layout"]!.AsObject().Remove("business_policy"); groups.Add(groups.First(g => g.Text("name") == "Google Services")!.DeepClone());
        Refuses(() => ClientSchemes.UpgradeLayout(scheme), "duplicate Google groups migrated ambiguously");
    }
}
