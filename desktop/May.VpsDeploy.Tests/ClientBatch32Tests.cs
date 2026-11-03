using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunClientBatch32Tests()
    {
        using var f = new Fixture(repository); ClientBatch32Model(f); await ClientBatch32Runtime(f);
        Console.WriteLine($"PASS: {assertions} round32 batch, native fragments, source identity and reviewed publication assertions; no production connections.");
    }
    private static JsonObject Batch32Scheme(Fixture f)
    {
        var scheme = OutputScheme(f); var landing = scheme["Nodes"]![2]!;
        landing["kind"] = "landing"; landing["transit_group"] = "US-West-LA Entry"; return scheme;
    }
    private void ClientBatch32Model(Fixture f)
    {
        var scheme = Batch32Scheme(f); var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray(); var ids = nodes.Select(n => n.Text("Id")).ToArray(); var original = ArchiveStore.Fingerprint(scheme);
        var move = ClientNodeBatch.Preview(scheme, "MoveStart", [ids[1]]);
        Check(move.Ready && move.Scheme["Nodes"]![0]!.Text("Id") == ids[1] && ArchiveStore.Fingerprint(scheme) == original, "batch preview mutated draft or used names as identities");
        move.Scheme["Nodes"]![0]!["sing_box"]!["password"] = "caller-mutation"; ClientNodeBatch.Apply(scheme, move);
        Check(scheme["Nodes"]![0]!.Text("sing_box.password") == nodes[1].Text("sing_box.password"), "batch trusted mutable preview contents");
        Refuses(() => ClientNodeBatch.Apply(scheme, move), "stale batch order applied");
        var sorted = ClientNodeBatch.Preview(scheme, "Sort", [ids[0], ids[1]]); ClientNodeBatch.Apply(scheme, sorted);
        Check(scheme["Nodes"]![0]!.Text("Id") == ids[0] && scheme["Nodes"]![2]!.Text("Id") == ids[2], "batch sorting moved unselected slots");
        Check(!ClientNodeBatch.Preview(scheme, "Remove", ids).Ready, "batch removed every entry");
        Check(!ClientNodeBatch.Preview(scheme, "Region", [ids[2]], "Europe Entry").Ready, "landing accepted as region entry");
        var orphan = ClientNodeBatch.Preview(scheme, "Region", [ids[0], ids[1]], "Europe Entry"); Check(!orphan.Ready, "moving region orphaned landing");
        scheme["Nodes"]![0]!["sing_box"]!["detour"] = "EntryB";
        Check(!ClientNodeBatch.Preview(scheme, "Remove", [ids[1]]).Ready, "bulk deletion broke native node upstream"); scheme["Nodes"]![0]!["sing_box"]!.AsObject().Remove("detour");
        scheme["Layout"]!["business_groups"]![0]!["default"] = "Landing";
        Check(!ClientNodeBatch.Preview(scheme, "Remove", [ids[2]]).Ready, "bulk deletion silently reset selected business default"); scheme["Layout"]!["business_groups"]![0]!["default"] = scheme.Text("Layout.default_exit_group");
        Refuses(() => ClientNodeBatch.Preview(scheme, "Remove", [ids[0], ids[0]]), "duplicate batch identities accepted");
        Refuses(() => ClientNodeBatch.Preview(scheme, "Region", [ids[0]], "unknown"), "unknown region accepted");
        var groupId = Guid.NewGuid().ToString("N"); foreach (var n in scheme["Nodes"]!.AsArray().Take(2)) n!["GroupOrigin"] = new JsonObject { ["Id"] = groupId };
        Check(!ClientNodeBatch.Preview(scheme, "DetachGroup", [ids[0]]).Ready && !ClientNodeBatch.Preview(scheme, "Remove", [ids[0]]).Ready, "group batch lost unselected group members");
        var detached = ClientNodeBatch.Preview(scheme, "DetachGroup", [ids[0], ids[1]]); ClientNodeBatch.Apply(scheme, detached);
        Check(scheme["Nodes"]![0]!["GroupOrigin"] == null && scheme["Nodes"]![1]!["GroupOrigin"] == null, "full group detach left links");
        scheme["Nodes"]![0]!["Source"] = new JsonObject { ["Kind"] = "Subscription", ["Id"] = Guid.NewGuid().ToString("N") };
        var conn = ClientNodeImport.ConnectionFingerprint(scheme["Nodes"]![0]!.AsObject()); ClientNodeBatch.Apply(scheme, ClientNodeBatch.Preview(scheme, "DetachSubscription", [ids[0]]));
        Check(scheme["Nodes"]![0]!.Text("Source.Kind") == "Manual" && ClientNodeImport.ConnectionFingerprint(scheme["Nodes"]![0]!.AsObject()) == conn, "subscription detach dropped connection");
        var frag = ClientNodeFragments.Preview(scheme, "SingBox", [ids[2]]); var native = ClientNodeFragments.Build(scheme, frag);
        Check(frag.Ready && frag.Rows.Count == 3 && frag.Rows.Count(r => r.Dependency) == 2 && frag.Groups.SequenceEqual(new[] { "US-West-LA Entry" }), "landing fragment did not disclose full region closure");
        Check(native["outbounds"]!.AsArray().Count == 4 && native["outbounds"]![2]!.Text("detour") == "US-West-LA Entry", "fragment dropped group or landing detour");
        scheme["Nodes"]![1]!["sing_box"]!["detour"] = "EntryA"; scheme["Nodes"]![0]!["sing_box"]!["detour"] = "EntryB";
        Check(!ClientNodeFragments.Preview(scheme, "SingBox", [ids[0]]).Ready, "cyclic fragment accepted");
        scheme["Nodes"]![0]!["sing_box"]!["detour"] = "Unknown policy"; Check(!ClientNodeFragments.Preview(scheme, "SingBox", [ids[0]]).Ready, "unknown policy flattened in fragment");
        scheme["Nodes"]![0]!["sing_box"]!.AsObject().Remove("detour"); scheme["Nodes"]![1]!["sing_box"]!.AsObject().Remove("detour");
        var alone = ClientNodeFragments.Preview(scheme, "Clash", [ids[0]]); Check(alone.Rows.Count == 1 && alone.Groups.Count == 0 && ClientNodeFragments.Build(scheme, alone)["proxies"]!.AsArray().Count == 1, "standalone fragment exposed unselected nodes");
        scheme["Nodes"]![0]!["clash"]!["ech-opts"] = new JsonObject { ["enable"] = true, ["config"] = "opaque==" };
        Refuses(() => ClientNodeFragments.Build(scheme, alone), "stale fragment reused after parameter change");
        var advanced = ClientNodeFragments.Build(scheme, ClientNodeFragments.Preview(scheme, "Clash", [ids[0]])); Check(advanced["proxies"]![0]!.Text("ech-opts.config") == "opaque==", "native fragment lost unshareable settings");
        scheme["OutputRules"] = ClientOutputRules.New(); scheme["OutputRules"]!["Enabled"] = true; scheme["OutputRules"]!["Prefix"] = "导出 · ";
        Check(ClientNodeFragments.Build(scheme, ClientNodeFragments.Preview(scheme, "SingBox", [ids[2]]))["outbounds"]![2]!.Text("tag") == "导出 · Landing", "fragment ignored output naming");
        scheme["OutputClients"] = "SingBox"; Refuses(() => ClientNodeFragments.Preview(scheme, "Clash", [ids[0]]), "fragment used unselected client");
    }
    private async Task ClientBatch32Runtime(Fixture f)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (string.IsNullOrEmpty(python) || !OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: round32 pinned Windows cores need MAY_TEST_PYTHON."); return; }
        var scheme = Batch32Scheme(f); var bench = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), python);
        var export = f.Paths.Resolve("exports"); Directory.CreateDirectory(export); var files = new[] { Path.Combine(export, "nodes.yaml"), Path.Combine(export, "nodes.json") };
        var id = scheme["Nodes"]![2]!.Text("Id"); var before = ArchiveStore.Fingerprint(scheme);
        foreach (var (format, file) in new[] { ("Clash", files[0]), ("SingBox", files[1]) })
        {
            var preview = ClientNodeFragments.Preview(scheme, format, [id]); await bench.SaveFragmentAsync(scheme, preview, file, default);
            await RefusesAsync(() => bench.SaveFragmentAsync(scheme, preview, file, default), "fragment overwrote existing file");
            using var stop = new CancellationTokenSource(); stop.Cancel(); var absent = Path.Combine(export, "canceled" + Path.GetExtension(file));
            try { await bench.SaveFragmentAsync(scheme, preview, absent, stop.Token); throw new Exception("canceled fragment succeeded"); } catch (OperationCanceledException) { Check(!File.Exists(absent), "cancel created fragment"); }
        }
        var imported = await bench.ReadSourcesAsync(files[0], files[1], default); Check(imported.Count == 3 && ArchiveStore.Fingerprint(scheme) == before, "native fragments did not reimport or mutated scheme");
        var merged = ClientSchemes.New(f.Paths); merged["Nodes"] = imported;
        foreach (var node in imported.OfType<JsonObject>()) { node["Id"] = Guid.NewGuid().ToString("N"); node["kind"] = "entry"; node["region_group"] = "US-West-LA Entry"; }
        // Native landing detours reference the disclosed selector. The importer
        // preserves these fields; complete output restores that selector by name.
        imported[2]!["kind"] = "landing"; imported[2]!["transit_group"] = "US-West-LA Entry";
        await bench.BuildAsync(merged, default); await bench.ValidateAsync(merged, default); Check(merged.Text("Candidate.ValidationStatus") == "Passed", "native merge round trip rejected by pinned cores");
        await bench.BuildAsync(scheme, default); await bench.ValidateAsync(scheme, default);
        var clash = Path.Combine(export, "review.yaml"); var sing = Path.Combine(export, "review.json"); var fp = ArchiveStore.Fingerprint(scheme);
        var review = await bench.PreviewPublishAsync(scheme, clash, sing, default);
        Check(ArchiveStore.Fingerprint(scheme) == fp && !File.Exists(clash) && !Directory.Exists(f.Paths.Resolve("private/client-publish")), "difference preview wrote metadata, journal or target");
        Check(review.Targets.All(t => t.BeforeHash == "missing" && t.Summary.Contains(t.Format == "Clash" ? "节点／出站：新增 3" : "节点／出站：新增 5")) && !string.Join(";", review.Targets).Contains("synthetic-a"), "diff summary missing changes or leaked credentials");
        File.WriteAllText(clash, "proxies: []\n"); Refuses(() => bench.PublishReviewed(scheme, review), "external target change overwritten"); Check(!File.Exists(sing), "stale review partially exported peer");
        review = await bench.PreviewPublishAsync(scheme, clash, sing, default); bench.PublishReviewed(scheme, review);
        Check(File.Exists(sing) && ClientSchemes.SourceFingerprint(sing) == scheme.Text("Candidate.SingBoxHash"), "reviewed export content mismatch");
        var same = await bench.PreviewPublishAsync(scheme, clash, sing, default); var journals = Directory.GetDirectories(f.Paths.Resolve("private/client-publish")).Length;
        bench.PublishReviewed(scheme, same); Check(Directory.GetDirectories(f.Paths.Resolve("private/client-publish")).Length == journals, "identical export created unnecessary transaction");
        var candidateFile = scheme.Text("Candidate.SingBox"); var candidateBytes = File.ReadAllBytes(candidateFile); File.AppendAllText(candidateFile, " ");
        Refuses(() => bench.PublishReviewed(scheme, same), "modified candidate reused reviewed export"); File.WriteAllBytes(candidateFile, candidateBytes);
        var sourceFile = scheme.Text("SingBox"); var sourceBytes = File.ReadAllBytes(sourceFile); File.AppendAllText(sourceFile, " ");
        Refuses(() => bench.PublishReviewed(scheme, same), "modified source template reused reviewed export"); File.WriteAllBytes(sourceFile, sourceBytes);
        var fragmentSource = Path.Combine(export, "source.json"); File.WriteAllText(fragmentSource, "{}"); scheme["Sources"] = new JsonObject { [fragmentSource] = ClientSchemes.SourceFingerprint(fragmentSource) };
        var sourced = ClientNodeFragments.Preview(scheme, "SingBox", [id]); File.WriteAllText(fragmentSource, "{\"changed\":true}");
        await RefusesAsync(() => bench.GenerateFragmentAsync(scheme, sourced, default), "fragment exported stale file-backed origin"); scheme.Remove("Sources");
        using (var large = new FileStream(clash, FileMode.Create, FileAccess.Write)) large.SetLength(16 * 1024 * 1024 + 1);
        await RefusesAsync(() => bench.PreviewPublishAsync(scheme, clash, sing, default), "oversized review target read without bound");
        scheme["Name"] = "Changed after preview"; Refuses(() => bench.PublishReviewed(scheme, same), "scheme identity changed after preview");
        File.WriteAllText(clash, "password: [private-parser-value"); await RefusesAsync(() => bench.PreviewPublishAsync(scheme, clash, sing, default), "malformed target parsed as empty");
        Check(!Directory.EnumerateFiles(export, ".may-fragment-*").Any(), "fragment temporary secrets retained");
    }
}
