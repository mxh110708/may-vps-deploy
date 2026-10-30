using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunClientGroupTests()
    {
        using var fixture = new Fixture(repository); await ClientGroupExperience(fixture);
        Console.WriteLine($"PASS: {assertions} reusable-group assertions; isolated sources and exports only.");
    }
    private async Task ClientGroupExperience(Fixture f)
    {
        var source = OutputScheme(f); var original = ArchiveStore.Fingerprint(source); var library = new ClientNodeGroupStore(f.Store);
        var ids = source["Nodes"]!.AsArray().Select(n => n!.Text("Id")).ToArray();
        var group = ClientNodeGroups.Capture(source, "Reusable region", ids); library.Save(group);
        Check(ArchiveStore.Fingerprint(source) == original && library.List().Count == 1, "capturing a group mutated its source scheme");
        var stored = f.Paths.Resolve("private/client-node-groups/" + group.Text("Id") + ".dotnet.private.json");
        Check(!File.ReadAllText(stored).Contains("synthetic-a") && library.Read(group.Text("Id"))["Nodes"]![0]!.Text("name") == "EntryA", "reusable group was not encrypted or read back");
        var first = ClientSchemes.New(f.Paths); var second = ClientSchemes.New(f.Paths); var wb = new ClientWorkbench(f.Store, new FakeTools(), new FakeAssets(), "unused");
        var preview = library.Preview(first, group.Text("Id")); Check(preview.Ready && first["Nodes"]!.AsArray().Count == 0, "preview changed the current scheme");
        library.Apply(first, group.Text("Id"), preview); library.Apply(second, group.Text("Id"), library.Preview(second, group.Text("Id"))); wb.Save(second);
        var stable = first["Nodes"]![0]!.Text("Id"); var secondSnapshot = ArchiveStore.Fingerprint(second);
        Check(first["Nodes"]!.AsArray().Count == 3 && first["Nodes"]![0]!.Text("Id") != ids[0] && ClientNodeGroups.MemberFingerprint(first["Nodes"]![0]!.AsObject()) == ClientNodeGroups.MemberFingerprint(group["Nodes"]![0]!.AsObject()), "group lost parameters or reused scheme member identity");
        Check(ClientSchemes.Specification(first)["groups"]!.AsArray().Count > 0, "group cannot generate a complete layout");
        Refuses(() => library.Save(group), "existing group overwritten without revision review"); Refuses(() => library.Delete(group.Text("Id")), "referenced group deleted");
        var collision = OutputScheme(f); Check(!library.Preview(collision, group.Text("Id")).Ready, "existing connections were silently adopted");
        Refuses(() => ClientNodeGroups.Capture(source, "orphan", [ids[2]]), "landing captured without its upstream entry");
        Refuses(() => ClientNodeGroups.Capture(source, "duplicate", [ids[0], ids[0]]), "duplicate group selection accepted");
        Refuses(() => ClientNodeGroups.Capture(source, "", ids), "empty group name accepted");
        var changedScheme = ClientSchemes.New(f.Paths); var stalePreview = library.Preview(changedScheme, group.Text("Id")); changedScheme["Name"] = "changed";
        Refuses(() => library.Apply(changedScheme, group.Text("Id"), stalePreview), "stale target preview applied");
        var local = first.DeepClone().AsObject(); local["Nodes"]![0]!["sing_box"]!["server_port"] = 9999; var localSnapshot = ArchiveStore.Fingerprint(local);
        Check(!library.Preview(local, group.Text("Id")).Ready, "local edit did not conflict with group refresh"); Refuses(() => library.Verify(local), "edited group exported"); Check(ArchiveStore.Fingerprint(local) == localSnapshot, "local conflict overwrote a draft");
        var sharePreview = ClientShareLinks.Preview(first); var exporter = new ClientShareExport(f.Store); var shareIds = sharePreview.Rows.Where(r => r.Ready).Select(r => r.Id).ToArray();
        Check(exporter.Generate(first, sharePreview, shareIds, "Plain").Contains("anytls://"), "group sharing cannot use the original exact connection");
        var exportRoot = f.Paths.Resolve("exports"); Directory.CreateDirectory(exportRoot);
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); ClientWorkbench? actual = null;
        if (!string.IsNullOrEmpty(python))
        {
            actual = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), python);
            await actual.BuildAsync(first, default); await actual.ValidateAsync(first, default);
            var yaml = Path.Combine(exportRoot, "group.yaml"); var json = Path.Combine(exportRoot, "group.json"); actual.PreparePublish(first, yaml, json); actual.Publish(first, yaml, json);
            var read = await actual.ReadSourcesAsync(yaml, json, default);
            var expected = group["Nodes"]!.AsArray().DeepClone().AsArray();
            foreach (var landing in expected.OfType<JsonObject>().Where(n => n.Text("kind") == "landing")) { landing["sing_box"]!["detour"] = landing.Text("transit_group"); landing["clash"]!["dialer-proxy"] = landing.Text("transit_group"); }
            Check(read.Count == 3 && read.OfType<JsonObject>().All(n => expected.OfType<JsonObject>().Any(m => m.Text("name") == n.Text("name") && ClientNodeImport.ConnectionFingerprint(m) == ClientNodeImport.ConnectionFingerprint(n))), "generated dual-client group differs from its original connection and modeled upstream");
        }
        var oldRevision = ClientNodeGroups.Revision(group); var next = group.DeepClone().AsObject(); next["Nodes"]![0]!["sing_box"]!["password"] = "synthetic-rotated"; next["Nodes"]![0]!["clash"]!["password"] = "synthetic-rotated";
        library.Save(next, oldRevision); Refuses(() => library.Verify(first), "changed library left old snapshot exportable");
        Refuses(() => exporter.Generate(first, ClientShareLinks.Preview(first), shareIds, "Base64"), "sharing bypassed group source revision");
        if (actual != null) Refuses(() => actual.PreparePublish(first, Path.Combine(exportRoot, "stale.yaml"), Path.Combine(exportRoot, "stale.json")), "validated candidate survived library credential rotation");
        Check(ArchiveStore.Fingerprint(wb.List().Single(s => s.Text("Id") == second.Text("Id"))) == secondSnapshot, "updating a group silently rewrote another saved scheme");
        library.Apply(first, next.Text("Id"), library.Preview(first, next.Text("Id"))); Check(first["Nodes"]![0]!.Text("Id") == stable && first["Candidate"] == null && first["Nodes"]![0]!.Text("sing_box.password") == "synthetic-rotated", "refresh changed stable identity or retained stale candidate");
        Refuses(() => library.Save(group, oldRevision), "concurrent group change overwritten");
        var captured = ClientNodeGroups.Capture(first, "Updated from reused scheme", first["Nodes"]!.AsArray().Select(n => n!.Text("Id")).ToArray(), group.Text("Id"));
        Check(captured["Nodes"]![0]!.Text("Id") == group["Nodes"]![0]!.Text("Id"), "recapture changed source member identity");
        var one = group.DeepClone().AsObject(); one["Nodes"] = new JsonArray(group["Nodes"]![0]!.DeepClone(), group["Nodes"]![1]!.DeepClone());
        var victim = first.DeepClone().AsObject(); victim["Layout"]!["business_groups"]![0]!["default"] = "Landing";
        var removal = ClientNodeGroups.Preview(victim, one); Check(removal.Ready && removal.Scheme["Layout"]!["business_groups"]![0]!.Text("default") == "", "removed business default fell back to a different exit");
        var movedRegion = group.DeepClone().AsObject(); movedRegion["Nodes"] = new JsonArray(group["Nodes"]![0]!.DeepClone()); movedRegion["Nodes"]![0]!["region_group"] = "Europe Entry"; var regionVictim = first.DeepClone().AsObject(); regionVictim["Layout"]!["business_groups"]![0]!["default"] = "US-West-LA Entry";
        var regionPreview = ClientNodeGroups.Preview(regionVictim, movedRegion); Check(regionPreview.Ready && regionPreview.Scheme["Layout"]!["business_groups"]![0]!.Text("default") == "", "empty regional default silently changed to another exit");
        var external = source["Nodes"]![0]!.DeepClone().AsObject(); external["Id"] = Guid.NewGuid().ToString("N"); external["name"] = "Dependent"; external["sing_box"]!["tag"] = "Dependent"; external["clash"]!["name"] = "Dependent"; external["sing_box"]!["detour"] = "Landing"; victim["Nodes"]!.AsArray().Add(external);
        Check(!ClientNodeGroups.Preview(victim, one).Ready, "member removal left an external upstream dangling");
        var raw = source.DeepClone().AsObject(); raw["Nodes"]![0]!["sing_box"]!["detour"] = "missing";
        Refuses(() => ClientNodeGroups.Capture(raw, "missing dependency", ids), "foreign native dependency captured");
        raw["Nodes"]![0]!["sing_box"]!["detour"] = "EntryB"; raw["Nodes"]![1]!["sing_box"]!["detour"] = "EntryA";
        Refuses(() => ClientNodeGroups.Capture(raw, "cyclic dependency", ids), "cyclic native dependency captured");
        var subscription = ClientSubscriptions.New("US-West-LA Entry"); subscription["Url"] = "https://example.invalid/private?key=synthetic-group-url"; source["NodeSources"] = new JsonArray(subscription); source["Nodes"]![0]!["Source"]!["Id"] = subscription.Text("Id");
        var subscriptionGroup = ClientNodeGroups.Capture(source, "Private source", [ids[0]]); library.Save(subscriptionGroup);
        Check(subscriptionGroup["NodeSources"]!.AsArray().Count == 1 && !File.ReadAllText(f.Paths.Resolve("private/client-node-groups/" + subscriptionGroup.Text("Id") + ".dotnet.private.json")).Contains("synthetic-group-url"), "subscription identity lost or URL leaked");
        var reusedSubscription = ClientSchemes.New(f.Paths); library.Apply(reusedSubscription, subscriptionGroup.Text("Id"), library.Preview(reusedSubscription, subscriptionGroup.Text("Id")));
        var recapturedSubscription = ClientNodeGroups.Capture(reusedSubscription, "Recaptured subscription", reusedSubscription["Nodes"]!.AsArray().Select(n => n!.Text("Id")).ToArray(), subscriptionGroup.Text("Id"), subscriptionGroup);
        Check(recapturedSubscription["NodeSources"]![0]!.Text("Url") == subscription.Text("Url"), "recapturing a reused group lost private source identity");
        var fileSource = f.Paths.Resolve("source-fingerprint.json"); File.WriteAllText(fileSource, "source-v1"); subscriptionGroup["Sources"] = new JsonObject { [fileSource] = ClientSchemes.SourceFingerprint(fileSource) };
        library.Save(subscriptionGroup, ClientNodeGroups.Revision(library.Read(subscriptionGroup.Text("Id")))); File.WriteAllText(fileSource, "source-v2");
        Refuses(() => library.Preview(ClientSchemes.New(f.Paths), subscriptionGroup.Text("Id")), "changed file source accepted by reused group");
        ClientNodeGroups.Detach(first, group.Text("Id")); Check(first["Nodes"]!.AsArray().Count == 3 && first["Nodes"]!.AsArray().All(n => n!["GroupOrigin"] == null), "detaching lost group members");
        ClientNodeGroups.Detach(second, group.Text("Id")); wb.Save(second); wb.Save(first); library.Delete(group.Text("Id"), first); Check(library.List().Count == 1, "unreferenced group deletion affected another group");
        Console.WriteLine("PASS: reusable groups, source rotation, conflicts, export dependencies and encrypted archive boundaries.");
    }
}
