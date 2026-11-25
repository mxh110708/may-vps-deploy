using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunClientTemplate38Tests()
    {
        using var f = new Fixture(repository); await ClientTemplate38Experience(f);
        Console.WriteLine($"PASS: {assertions} template version, dependency, immutable source, diff, cancellation, scoped recovery and actual core validation assertions; no production connections.");
    }
    private async Task ClientTemplate38Experience(Fixture f)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python";
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        var library = new ClientTemplateStore(f.Store, tools, assets, python); var built = library.BuiltIn(); var original = ArchiveStore.Fingerprint(built);
        Check(library.List().Count == 1 && built.Number("Revision") == ArchiveStore.ReadJson(f.Paths.Resolve("config/client-templates.json")).Number("Revision"), "builtin catalog unavailable");
        foreach (var edit in new Action<JsonObject>[] { d => d["Unknown"] = true, d => d["Id"] = "../escape", d => d["Revision"] = 33,
            d => d["Parameters"]!["ClashMixedPort"] = 0, d => d["Parameters"]!["RouteMixedPort"] = 65536, d => d["Parameters"]!["RouteMixedPort"] = "2080",
            d => d["Parameters"]!["TunMtu"] = 1279, d => d["Parameters"]!["TunMtu"] = 9001, d => d["Parameters"]!["AllowLan"] = "true", d => d["Parameters"]!["Command"] = "ignored",
            d => d["Parameters"]!["Mode"] = "script", d => d["Layout"]!["default_exit_members"] = new JsonArray("Default Exit"), d => d["Layout"]!["business_groups"]![0]!["default"] = "unknown-node" })
        { var invalid = built.DeepClone().AsObject(); edit(invalid); Refuses(() => ClientTemplates.Validate(invalid), "invalid or executable template parameter accepted"); }
        Check(ArchiveStore.Fingerprint(built) == original, "validation mutated builtin");
        var dependencies = await library.InspectAsync(built, default); Check(dependencies["Dependencies"]!.AsArray().Any(d => d!.Text("Status") == "RemoteNotFetched") && dependencies["Dependencies"]!.AsArray().Count(d => d!.Text("Status") == "PinnedArtifactAvailable") == 3, "dependency inspection mixed static remote declarations with pinned local artifacts");
        var builtinChild = library.Draft(built, false); await library.SaveVersionAsync(builtinChild, default);
        Check(ArchiveStore.Fingerprint(library.Read(built.Text("Id"), built.Number("Revision"))) == original && File.Exists(f.Paths.Resolve("private/client-templates/versions/" + built.Text("Id") + "-" + built.Number("Revision") + ".private.json")), "deriving builtin revision lost its immutable parent snapshot");
        var clashOnly = library.Draft(built, true); clashOnly["Clients"] = "Clash"; clashOnly["Bases"]!.AsObject().Remove("SingBox"); library.BindCurrentCores(clashOnly); await library.SaveVersionAsync(clashOnly, default);
        Check(clashOnly["Cores"]!.AsObject().Count == 1 && clashOnly["Cores"]!["mihomo"] != null, "single-client template pinned unrelated client cores");
        var doc = library.Draft(built, true); doc["Name"] = "Synthetic template"; doc["Parameters"]!["ClashMixedPort"] = 19980; doc["Parameters"]!["RouteMixedPort"] = 19981; doc["Parameters"]!["TunMtu"] = 1400; doc["Parameters"]!["LogLevel"] = "warn"; doc["Parameters"]!["Mode"] = "global";
        await library.SaveVersionAsync(doc, default);
        await RefusesAsync(() => library.SaveVersionAsync(doc, default), "immutable revision overwritten");
        var two = library.Draft(doc, false); two["Parameters"]!["ClashMixedPort"] = 19982; await library.SaveVersionAsync(two, default);
        Check(library.Read(doc.Text("Id"), 1).Number("Parameters.ClashMixedPort") == 19980 && library.Read(doc.Text("Id"), 2).Number("Parameters.ClashMixedPort") == 19982, "new revision changed old snapshot");
        var staleChild = library.Draft(doc, false); await RefusesAsync(() => library.SaveVersionAsync(staleChild, default), "stale parent replaced later revision");
        var bad = library.Draft(two, false); bad["Bases"]!["Clash"] = "proxies: [{name: secret, type: ss, server: example.test}]\n";
        await RefusesAsync(() => library.SaveVersionAsync(bad, default), "fixed credential node entered reusable base");
        var scheme = OutputScheme(f); var schemeFile = ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")); f.Store.WriteSecret(schemeFile, scheme);
        var beforeFile = File.ReadAllBytes(schemeFile); var beforeNodes = scheme["Nodes"]!.DeepClone();
        var preview = await library.PreviewAsync(scheme.Text("Id"), doc.Text("Id"), 1, default);
        Check(File.ReadAllBytes(schemeFile).SequenceEqual(beforeFile) && !ClientTemplates.Journals(f.Store).Any(), "preview changed saved scheme or journal");
        Check(preview.Summary.Contains("DNS") && preview.Summary.Contains("监听") && !preview.Summary.Contains("synthetic-a"), "review missing actual configuration delta or leaked credentials");
        using (var cancelled = new CancellationTokenSource()) { cancelled.Cancel(); var caught = false; try { await library.ApplyAsync(preview, cancelled.Token); } catch (OperationCanceledException) { caught = true; } Check(caught && File.ReadAllBytes(schemeFile).SequenceEqual(beforeFile), "cancelled apply changed scheme"); }
        var tampered = preview with { After = preview.After.DeepClone().AsObject() }; tampered.After["Nodes"]![0]!["name"] = "tampered";
        await RefusesAsync(() => library.ApplyAsync(tampered, default), "mutable preview rewrote nodes");
        var sourceBytes = File.ReadAllBytes(scheme.Text("Clash")); File.AppendAllText(scheme.Text("Clash"), "\n# changed after review\n");
        await RefusesAsync(() => library.ApplyAsync(preview, default), "source file change after review was ignored"); File.WriteAllBytes(scheme.Text("Clash"), sourceBytes);
        var application = await library.ApplyAsync(preview, default); var applied = f.Store.ReadSecret(schemeFile);
        Check(applied.Number("TemplateReference.Revision") == 1 && JsonNode.DeepEquals(applied["Nodes"], beforeNodes) && applied["Candidate"] == null && applied.Text("Targets.Clash") == scheme.Text("Targets.Clash"), "template apply changed nodes, provenance or export targets");
        library.Verify(applied);
        Check(ArchiveStore.ReadJson(applied.Text("SingBox"))["inbounds"]![0]!.Number("listen_port") == 19981, "parameterized Route listener not materialized");
        var contents = File.ReadAllText(applied.Text("Clash")); Check(contents.Contains("mixed-port: 19980") && contents.Contains("log-level: warning"), "Mihomo parameter mapping missing");
        var workbench = new ClientWorkbench(f.Store, tools, assets, python); var candidate = await workbench.BuildAsync(applied, default);
        if (OperatingSystem.IsWindows()) { await workbench.ValidateAsync(applied, default); Check(candidate.Text("ValidationStatus") == "Passed" && applied.Text("Candidate.ValidationStatus") == "Passed", "parameterized version failed actual selected client cores"); }
        else Console.WriteLine("SKIP: packaged Windows client-core execution; controller source/model and rendering tests still run.");
        Check(candidate["TemplateSnapshot"] != null, "candidate lost fixed template dependency snapshot");
        var validCandidate = applied["Candidate"]!.DeepClone(); var noOp = await library.PreviewAsync(applied.Text("Id"), doc.Text("Id"), 1, default); var noOpResult = await library.ApplyAsync(noOp, default);
        Check(noOpResult == "" && JsonNode.DeepEquals(f.Store.ReadSecret(schemeFile)["Candidate"], validCandidate), "same version unnecessarily cleared validated candidate or added journal");
        var bytes = File.ReadAllBytes(applied.Text("Clash")); File.AppendAllText(applied.Text("Clash"), "\n# external drift\n");
        Refuses(() => library.Verify(applied), "externally edited immutable template accepted"); await RefusesAsync(() => workbench.ValidateAsync(applied, default), "template drift allowed candidate validation"); File.WriteAllBytes(applied.Text("Clash"), bytes);
        // Unrelated node edits survive restoration; base-field edits do not get overwritten.
        applied = f.Store.ReadSecret(schemeFile); applied["Nodes"]![0]!["name"] = "Unrelated rename"; f.Store.WriteSecret(schemeFile, applied);
        var restore = library.PreviewRestore(application); library.Restore(restore); var restored = f.Store.ReadSecret(schemeFile);
        Check(JsonNode.DeepEquals(ClientTemplates.Fields(restored), ClientTemplates.Fields(scheme)) && restored["Nodes"]![0]!.Text("name") == "Unrelated rename" && restored["Candidate"] == null, "restore clobbered unrelated node changes or retained stale candidate");
        Refuses(() => library.PreviewRestore(application), "already restored application repeated");
        restored["Nodes"]![0]!["name"] = scheme["Nodes"]![0]!.Text("name"); f.Store.WriteSecret(schemeFile, restored);
        preview = await library.PreviewAsync(scheme.Text("Id"), doc.Text("Id"), 2, default);
        restored["Name"] = "external saved change"; f.Store.WriteSecret(schemeFile, restored);
        await RefusesAsync(() => library.ApplyAsync(preview, default), "stale saved scheme overwritten after review");
        preview = await library.PreviewAsync(scheme.Text("Id"), doc.Text("Id"), 2, default); application = await library.ApplyAsync(preview, default);
        applied = f.Store.ReadSecret(schemeFile); applied["Layout"]!["business_groups"]![0]!["default"] = "Direct Route"; f.Store.WriteSecret(schemeFile, applied);
        Refuses(() => library.PreviewRestore(application), "restore overwrote newer per-scheme base/layout change");
        // Simulate a lost local commit acknowledgement. Recovery reconciles exact fields.
        var journal = ClientTemplates.Journals(f.Store).Single(j => j.Text("Id") == application); applied = ClientTemplates.ReplaceFields(applied, journal["After"]!.AsObject()); f.Store.WriteSecret(schemeFile, applied);
        journal["Phase"] = "Prepared"; var journalFile = f.Paths.Resolve("private/client-templates/applications/" + application + ".private.json"); f.Store.WriteSecret(journalFile, journal);
        Refuses(() => ClientSourceBarrier.RequireAvailable(f.Store, "Scheme", scheme.Text("Id")), "pending template did not block downstream node source use");
        Refuses(() => workbench.Save(applied), "normal save overwrote unresolved template transaction");
        library.Restore(library.PreviewRestore(application)); Check(ClientTemplates.Journals(f.Store).Single(j => j.Text("Id") == application).Text("Phase") == "RolledBack", "lost acknowledgement was replayed or left pending");
    }
}
