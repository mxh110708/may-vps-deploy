using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunClientOutputTests()
    {
        using var f = new Fixture(repository); await ClientOutputExperience(f); ClientSubscriptionExperience(f); await SubscriptionDownloadExperience();
        Console.WriteLine($"PASS: {assertions} output processing, source reconciliation and bounded HTTP assertions; isolated local services only.");
    }
    private static JsonObject OutputScheme(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths);
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("anytls://synthetic-a@entry.example:443?sni=example.com#EntryA\nanytls://synthetic-b@entry.example:444?sni=example.com#EntryB\nss://aes-128-gcm:synthetic-c@landing.example:8443#Landing", scheme, "US-West-LA Entry")); return scheme;
    }
    private async Task ClientOutputExperience(Fixture f)
    {
        var scheme = OutputScheme(f); var snapshot = ArchiveStore.Fingerprint(scheme);
        Check(ClientOutputRules.Preview(scheme).Ready && ArchiveStore.Fingerprint(scheme) == snapshot, "disabled rules changed sources");
        var rules = ClientOutputRules.New(); rules["Enabled"] = true; rules["Exclude"] = "entryb"; rules["Prefix"] = "May · "; rules["Find"] = "Entry"; rules["Replace"] = "Gateway"; rules["Sort"] = "NameDescending";
        scheme["Nodes"]![0]!["sing_box"]!["connect_timeout"] = "7s";
        scheme["Layout"]!["business_groups"]![0]!["default"] = "Landing";
        scheme["OutputRules"] = rules; snapshot = ArchiveStore.Fingerprint(scheme); var preview = ClientOutputRules.Preview(scheme);
        Check(preview.Ready && preview.Rows.Count(r => r.Included) == 2 && preview.Scheme["Nodes"]![0]!.Text("name") == "May · Landing", "filters, literal replacement or output sorting failed");
        Check(ArchiveStore.Fingerprint(scheme) == snapshot && scheme["Nodes"]![0]!.Text("name") == "EntryA", "preview rewrote original node or references");
        Check(preview.Scheme["Nodes"]![1]!.Text("Id") == scheme["Nodes"]![0]!.Text("Id") && preview.Scheme["Nodes"]![1]!.Text("sing_box.connect_timeout") == "7s", "output dropped stable identity or native advanced settings");
        Check(preview.Scheme["Layout"]!["business_groups"]![0]!.Text("default") == "May · Landing", "display name did not update business reference");
        var spec = ClientSchemes.Specification(scheme); Check(spec["remove_nodes"]!.AsArray().Any(n => n!.ToString() == "EntryB") && spec["rename_nodes"]!.Text("EntryA") == "May · GatewayA", "filtered and renamed source nodes were not owned by the export specification");
        Check(ClientCapabilities.Inspect(preview.Scheme).All(r => r.Ready) && ClientCapabilities.Inspect(preview.Scheme).Count == 4, "selected-client report missing entries");
        var noSing = scheme.DeepClone().AsObject(); noSing["Nodes"]![0]!.AsObject().Remove("sing_box"); Refuses(() => ClientSchemes.Specification(noSing), "missing selected-client config silently omitted"); noSing["OutputClients"] = "Clash";
        Check(ClientSchemes.Specification(noSing)["client_formats"]!.AsArray().Count == 1, "single-client generation required unselected configuration");
        void Bad(string key, string value, string message) { var bad = scheme.DeepClone().AsObject(); bad["OutputRules"]![key] = value; Check(!ClientOutputRules.Preview(bad).Ready, message); Refuses(() => ClientSchemes.Specification(bad), message + " build gate"); }
        Bad("Include", "absent", "empty output fell back to direct"); Bad("Exclude", "Entry", "orphan landing remained usable"); Bad("Prefix", new string('x', 121), "overlong names accepted"); Bad("Sort", "Script", "executable processing accepted");
        var collision = OutputScheme(f); var collisionRules = ClientOutputRules.New(); collisionRules["Enabled"] = true; collisionRules["Find"] = "EntryA"; collisionRules["Replace"] = "EntryB"; collision["OutputRules"] = collisionRules;
        var unknown = scheme.DeepClone().AsObject(); unknown["OutputRules"]!["Script"] = "unsupported"; Check(!ClientOutputRules.Preview(unknown).Ready, "unknown processing field silently ignored");
        Check(!ClientOutputRules.Preview(collision).Ready, "output reused another source alias"); collisionRules["Replace"] = "DIRECT"; Check(!ClientOutputRules.Preview(collision).Ready, "output collided with a built-in group");
        var upstream = OutputScheme(f); upstream["Nodes"]![0]!["sing_box"]!["detour"] = "EntryB"; upstream["OutputRules"] = ClientOutputRules.New(); upstream["OutputRules"]!["Enabled"] = true; upstream["OutputRules"]!["Prefix"] = "Out-";
        var upstreamSnapshot = ArchiveStore.Fingerprint(upstream); var upstreamPreview = ClientOutputRules.Preview(upstream);
        Check(upstreamPreview.Ready && upstreamPreview.Scheme["Nodes"]![0]!.Text("sing_box.detour") == "Out-EntryB" && ArchiveStore.Fingerprint(upstream) == upstreamSnapshot, "native upstream reference was not mapped without source mutation");
        upstream["OutputRules"]!["Exclude"] = "EntryB"; Check(!ClientOutputRules.Preview(upstream).Ready, "filtered upstream became another output");
        var lostDefault = OutputScheme(f); lostDefault["Layout"]!["business_groups"]![0]!["default"] = "Landing"; lostDefault["OutputRules"] = ClientOutputRules.New(); lostDefault["OutputRules"]!["Enabled"] = true; lostDefault["OutputRules"]!["Exclude"] = "Landing";
        Check(!ClientOutputRules.Preview(lostDefault).Ready, "filtered business default silently fell back");
        var beforeApply = ArchiveStore.Fingerprint(scheme); ClientOutputRules.Apply(scheme, rules, beforeApply); Refuses(() => ClientOutputRules.Apply(scheme, rules, "stale"), "stale output preview applied");
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); if (string.IsNullOrEmpty(python)) return;
        var workbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), python);
        var invalidEndpoint = scheme.DeepClone().AsObject(); invalidEndpoint["Nodes"]![0]!["sing_box"]!.AsObject().Remove("server");
        Check(ClientCapabilities.Inspect(ClientOutputRules.Preview(invalidEndpoint).Scheme).Any(r => !r.Ready), "capability report accepted incomplete native parameters");
        await RefusesAsync(() => workbench.BuildAsync(invalidEndpoint, CancellationToken.None), "generation did not enforce capability report");
        var sources = new[] { scheme.Text("Clash"), scheme.Text("SingBox") }.ToDictionary(p => p, ClientSchemes.SourceFingerprint); var originalNodes = ArchiveStore.Fingerprint(scheme["Nodes"]!);
        await workbench.BuildAsync(scheme, CancellationToken.None); await workbench.ValidateAsync(scheme, CancellationToken.None);
        Check(scheme.Text("Candidate.ValidationStatus") == "Passed" && ArchiveStore.Fingerprint(scheme["Nodes"]!) == originalNodes && sources.All(s => ClientSchemes.SourceFingerprint(s.Key) == s.Value), "real output generation changed source nodes or templates");
        var imported = await workbench.ReadSourcesAsync(scheme.Text("Candidate.Clash"), scheme.Text("Candidate.SingBox"), CancellationToken.None);
        Check(imported.Count == 2 && imported.All(n => n!.Text("name").StartsWith("May · ")) && imported.All(n => !n!.Text("name").Contains("EntryB")), "real generated outputs retained filtered nodes or raw names");
        var clash = f.Paths.Resolve("exports/processed.yaml"); var sing = f.Paths.Resolve("exports/processed.json"); workbench.PreparePublish(scheme, clash, sing); workbench.Publish(scheme, clash, sing);
        var exported = ClientSchemes.SourceFingerprint(sing); scheme["OutputRules"]!["Prefix"] = "Changed-"; Refuses(() => workbench.PreparePublish(scheme, clash, sing), "changed rules reused validated candidate");
        Check(ClientSchemes.SourceFingerprint(sing) == exported, "stale rule check changed existing exported configuration");
        var strict = OutputScheme(f); strict["OutputRules"] = ClientOutputRules.New(); strict["OutputRules"]!["Enabled"] = true; strict["OutputRules"]!["Exclude"] = "EntryB";
        var custom = ArchiveStore.ReadJson(strict.Text("SingBox")); custom["outbounds"]!.AsArray().Add(new JsonObject { ["type"] = "selector", ["tag"] = "Private choice", ["outbounds"] = new JsonArray("DIRECT", "EntryB"), ["default"] = "EntryB" });
        var customFile = f.Paths.Resolve("custom/authority.json"); ArchiveStore.WriteJson(customFile, custom); strict["SingBox"] = customFile; strict["SourceMode"] = "ExistingAuthority";
        await RefusesAsync(() => workbench.BuildAsync(strict, CancellationToken.None), "custom selector silently fell back from filtered default to DIRECT");
        custom["outbounds"]!.AsArray().Single(n => n!.Text("tag") == "Private choice")!["default"] = "DIRECT"; ArchiveStore.WriteJson(customFile, custom);
        await workbench.BuildAsync(strict, CancellationToken.None); await workbench.ValidateAsync(strict, CancellationToken.None);
        Check(scheme["Nodes"]![0]!.Text("name") == "EntryA" && strict.Text("Candidate.ValidationStatus") == "Passed", "explicit custom default could not generate or processing changed sources");
    }
    private void ClientSubscriptionExperience(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths); var source = ClientSubscriptions.New("US-West-LA Entry"); source["Url"] = "https://example.invalid/sub?key=synthetic-private-value";
        var a = "anytls://synthetic-a@entry.example:443?sni=example.com#A"; var b = "anytls://synthetic-b@entry.example:444?sni=example.com#B"; var body = a + "\n" + b;
        Check(!ClientSubscriptions.Label(source).Contains("key=") && !ClientSubscriptions.Label(source).Contains("synthetic-private"), "source label disclosed secret URL query");
        Check(ClientSubscriptions.Decode(Convert.ToBase64String(Encoding.UTF8.GetBytes(body)).TrimEnd('=')) == body, "unpadded subscription Base64 failed");
        var fingerprint = ArchiveStore.Fingerprint(scheme); var initial = ClientSubscriptions.Preview(scheme, source, body);
        Check(initial.Ready && initial.Changes.Count(c => c.Kind == "Added") == 2 && ArchiveStore.Fingerprint(scheme) == fingerprint, "subscription preview changed draft or missed nodes");
        ClientSubscriptions.Apply(scheme, initial); var idA = scheme["Nodes"]![0]!.Text("Id"); var idB = scheme["Nodes"]![1]!.Text("Id"); scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
        var duplicateSource = ClientSubscriptions.New("US-West-LA Entry"); duplicateSource["Url"] = source.Text("Url"); Check(!ClientSubscriptions.Preview(scheme, duplicateSource, body).Ready, "duplicate subscription address created another owner");
        var swapped = scheme.DeepClone().AsObject(); swapped["Layout"]!["business_groups"]![0]!["default"] = "A";
        ClientSubscriptions.Apply(swapped, ClientSubscriptions.Preview(swapped, source, a.Replace("#A", "#B") + "\n" + b.Replace("#B", "#A")));
        Check(swapped["Layout"]!["business_groups"]![0]!.Text("default") == "B" && swapped["Nodes"]![0]!.Text("Id") == idA, "simultaneous source rename swapped connection identity or chained reference rewrites");
        var noop = ClientSubscriptions.Preview(scheme, source, body); ClientSubscriptions.Apply(scheme, noop);
        Check(scheme["Candidate"] != null && scheme["Nodes"]![0]!.Text("Id") == idA && scheme["Nodes"]![1]!.Text("Id") == idB, "unchanged subscription lost identities or invalidated configuration");
        scheme["Layout"]!["business_groups"]![0]!["default"] = "A"; var renamed = ClientSubscriptions.Preview(scheme, source, body.Replace("#A", "#NewA")); ClientSubscriptions.Apply(scheme, renamed);
        Check(scheme["Nodes"]![0]!.Text("Id") == idA && scheme["Nodes"]![0]!.Text("name") == "NewA" && scheme["Layout"]!["business_groups"]![0]!.Text("default") == "NewA" && scheme["Candidate"] == null, "source display rename lost identity or references");
        var changedBody = body.Replace("#A", "#NewA").Replace("synthetic-a@", "synthetic-new@"); var changed = ClientSubscriptions.Preview(scheme, source, changedBody);
        Check(changed.Changes.Count(c => c.Kind == "Changed") == 1 && changed.Changes.All(c => !c.Detail.Contains("synthetic-new")), "parameter diff missing or revealed credentials"); ClientSubscriptions.Apply(scheme, changed);
        Check(scheme["Nodes"]![0]!.Text("Id") == idA && scheme["Nodes"]![0]!.Text("sing_box.password") == "synthetic-new", "confirmed source change did not retain identity");
        scheme["Nodes"]![0]!["sing_box"]!["password"] = "synthetic-local-edit"; var local = ClientSubscriptions.Preview(scheme, source, changedBody); ClientSubscriptions.Apply(scheme, local);
        Check(scheme["Nodes"]![0]!.Text("sing_box.password") == "synthetic-local-edit", "unchanged upstream overwrote local edit");
        var conflict = ClientSubscriptions.Preview(scheme, source, changedBody.Replace("synthetic-new@", "synthetic-next@")); fingerprint = ArchiveStore.Fingerprint(scheme);
        Check(!conflict.Ready && conflict.Changes.Any(c => c.Kind == "Conflict"), "concurrent local/upstream edit not flagged"); Refuses(() => ClientSubscriptions.Apply(scheme, conflict), "conflicting source preview applied"); Check(ArchiveStore.Fingerprint(scheme) == fingerprint, "conflict mutated source scheme");
        var partial = ClientSubscriptions.Preview(scheme, source, changedBody + "\nhy2://unsupported@bad.example:443?unsupported=1"); Check(!partial.Ready, "partial source parse could remove unparsed old connections");
        var stale = ClientSubscriptions.Preview(scheme, source, changedBody); scheme["Name"] = "changed"; Refuses(() => ClientSubscriptions.Apply(scheme, stale), "stale source preview applied");
        ClientSubscriptions.Detach(scheme["Nodes"]![0]!.AsObject()); var newSource = ClientSubscriptions.Preview(scheme, source, changedBody.Replace("synthetic-new@", "synthetic-next@")); ClientSubscriptions.Apply(scheme, newSource);
        Check(scheme["Nodes"]!.AsArray().Any(n => n!.Text("Id") == idA && n.Text("Source.Kind") == "Manual") && scheme["Nodes"]!.AsArray().Count == 3, "detached local node was reclaimed by source refresh");
        Check(ClientSubscriptions.Preview(scheme, source, changedBody.Replace("synthetic-new@", "synthetic-next@")).Ready, "automatic collision suffix did not remain stable on refresh");
        scheme["Layout"]!["business_groups"]![0]!["default"] = "B"; var removal = ClientSubscriptions.Preview(scheme, source, changedBody.Split('\n')[0].Replace("synthetic-new@", "synthetic-next@"));
        Check(removal.Changes.Any(c => c.Kind == "Impact"), "source removal missed dependency impact"); ClientSubscriptions.Apply(scheme, removal);
        Check(scheme["Layout"]!["business_groups"]![0]!.Text("default") == "" && scheme["Nodes"]!.AsArray().All(n => n!.Text("Id") != idB), "removed business default silently fell back or retained stale node");
        var empty = ClientSubscriptions.Preview(scheme, source, ""); Check(!empty.Ready, "empty subscription accepted"); Refuses(() => ClientSubscriptions.Apply(scheme, empty), "empty source cleared existing nodes");
        Refuses(() => ClientSubscriptions.Preview(scheme, source, "<html>https://example.invalid</html>"), "HTML source accepted");
        var unsafeSource = source.DeepClone().AsObject(); unsafeSource["Url"] = "http://example.invalid/sub"; Refuses(() => ClientSubscriptions.Validate(unsafeSource), "insecure remote subscription accepted");
        unsafeSource["Url"] = "https://name:secret@example.invalid/sub"; Refuses(() => ClientSubscriptions.Validate(unsafeSource), "embedded URL authentication accepted");
        unsafeSource["Url"] = source.Text("Url"); unsafeSource["Network"] = "Proxy"; unsafeSource["Proxy"] = "http://name:secret@127.0.0.1:7897"; Refuses(() => ClientSubscriptions.Validate(unsafeSource), "proxy authentication silently changed");
        new ClientWorkbench(f.Store, new FakeTools(), new FakeAssets(), "unused").Save(scheme);
        var file = f.Paths.Resolve("private/client-schemes/" + scheme.Text("Id") + ".dotnet.private.json"); Check(!File.ReadAllText(file).Contains("synthetic-private-value") && f.Store.ReadSecret(file)["NodeSources"]![0]!.Text("Url") == source.Text("Url"), "source URL not protected with the scheme");
    }
}
