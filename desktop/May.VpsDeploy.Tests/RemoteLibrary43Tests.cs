using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunRemoteLibrary43Tests()
    {
        using var f = new Fixture(repository); await RemoteLibrary43Experience(f);
        Console.WriteLine($"PASS: {assertions} remote source, immutable cache, diff, cancellation, identity, import and scoped template recovery assertions.");
    }
    private async Task RemoteLibrary43Experience(Fixture f)
    {
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64");
        var templates = new ClientTemplateStore(f.Store, new ExternalToolRunner(), assets, Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python");
        var fetch = new Remote43Fetch(); var manager = new RemoteLibrarySources(f.Store, templates, fetch);
        JsonObject Definition(string kind) { var source = ClientSubscriptions.New(""); source["Url"] = "https://library.example.test/data?access=synthetic-secret"; source["Kind"] = kind; source["ExpectedSha256"] = ""; return source; }
        var definition = Definition("Template"); var id = definition.Text("Id"); manager.Register(definition);
        var badDefinition = Definition("Template"); badDefinition["Url"] = "http://localhost/source"; Refuses(() => manager.Register(badDefinition), "remote library accepted plain HTTP");
        var document = templates.Draft(templates.BuiltIn(), true); document["Name"] = "Remote synthetic template";
        fetch.Content = document.ToJsonString(); var digest = await manager.FetchAsync(id, default);
        Check(templates.List().Count == 1 && manager.Read(id)["Versions"]!.AsArray().Count == 1, "fetch applied a template or failed to cache");
        var review = manager.Preview(id, digest);
        Check(review.Summary.Contains(digest) && !review.Summary.Contains("synthetic-secret") && review.Summary.Contains("使用者 0"), "unsafe or incomplete source review");
        var before = ArchiveStore.Fingerprint(manager.Read(id)); fetch.Content = "<html>failure</html>";
        await RefusesAsync(() => manager.FetchAsync(id, default), "invalid remote data replaced cache"); Check(ArchiveStore.Fingerprint(manager.Read(id)) == before, "failed fetch mutated last good cache");
        fetch.Content = document.ToJsonString(); using (var cancelled = new CancellationTokenSource()) { cancelled.Cancel(); var caught = false; try { await manager.FetchAsync(id, cancelled.Token); } catch (OperationCanceledException) { caught = true; } Check(caught && before == ArchiveStore.Fingerprint(manager.Read(id)), "cancelled fetch changed cache"); }
        await manager.ImportAsync(review, default); var localId = review.Document.Text("Id");
        Check(localId != document.Text("Id") && templates.Read(localId, 1).Text("Name") == document.Text("Name"), "remote template took over an existing identity");
        await manager.ImportAsync(manager.Preview(id, digest), default); Check(templates.List().Count(d => d.Text("Id") == localId) == 1, "unchanged import created duplicate revision");
        var scheme = OutputScheme(f); var schemeFile = ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")); f.Store.WriteSecret(schemeFile, scheme);
        var application = await templates.ApplyAsync(await templates.PreviewAsync(scheme.Text("Id"), localId, 1, default), default); var applied = File.ReadAllBytes(schemeFile);
        document["Revision"] = 2; document["Parameters"]!["RouteMixedPort"] = 19043; fetch.Content = document.ToJsonString(); var digest2 = await manager.FetchAsync(id, default); var second = manager.Preview(id, digest2);
        Check(second.Summary.Contains("使用者 1") && second.Summary.Contains("Parameters") && File.ReadAllBytes(schemeFile).SequenceEqual(applied), "consumer impact missing or staged update mutated scheme");
        var edited = second with { Document = second.Document.DeepClone().AsObject() }; edited.Document["Name"] = "tampered"; await RefusesAsync(() => manager.ImportAsync(edited, default), "mutable review bypassed source snapshot");
        await manager.ImportAsync(second, default); Check(templates.Read(localId, 1).Number("Parameters.RouteMixedPort") != 19043 && templates.Read(localId, 2).Number("Parameters.RouteMixedPort") == 19043 && File.ReadAllBytes(schemeFile).SequenceEqual(applied), "new revision overwrote old template or consumer");
        await RefusesAsync(() => manager.ImportAsync(second, default), "stale import was replayed");
        document["Name"] = "changed same version"; fetch.Content = document.ToJsonString(); await RefusesAsync(() => manager.FetchAsync(id, default), "same upstream revision changed bytes");
        document["Id"] = Guid.NewGuid().ToString("N"); document["Revision"] = 3; fetch.Content = document.ToJsonString(); await RefusesAsync(() => manager.FetchAsync(id, default), "upstream source changed object identity");
        var restoreVersion = manager.Preview(id, digest); await manager.ImportAsync(restoreVersion, default); Check(templates.Read(localId, 3).Number("Parameters.RouteMixedPort") == templates.Read(localId, 1).Number("Parameters.RouteMixedPort"), "historical cache cannot create recoverable template revision");
        templates.Restore(templates.PreviewRestore(application)); Check(JsonNode.DeepEquals(ClientTemplates.Fields(f.Store.ReadSecret(schemeFile)), ClientTemplates.Fields(scheme)), "remote template application failed scoped restore");
        var rulesDefinition = Definition("RuleSet"); manager.Register(rulesDefinition); var ruleId = rulesDefinition.Text("Id");
        var rule = new JsonObject { ["Schema"] = 1, ["Id"] = "remote-43-test", ["Name"] = "Synthetic rules", ["Revision"] = "1.0.0", ["Rules"] = new JsonArray(new JsonObject { ["Kind"] = "Suffix", ["Value"] = "example.test" }) };
        fetch.Content = rule.ToJsonString(); var rd = await manager.FetchAsync(ruleId, default); await manager.ImportAsync(manager.Preview(ruleId, rd), default); var sets = new ServerRuleSetStore(f.Store); var oldRules = sets.Read(rule.Text("Id"));
        rule["Revision"] = "1.1.0"; rule["Rules"]!.AsArray().Add(new JsonObject { ["Kind"] = "Cidr", ["Value"] = "192.0.2.0/24" }); fetch.Content = rule.ToJsonString(); rd = await manager.FetchAsync(ruleId, default); await manager.ImportAsync(manager.Preview(ruleId, rd), default);
        var newer = sets.Read(rule.Text("Id")); Check(newer["Versions"]!.AsArray().Count == 2 && ServerRuleSetStore.Current(oldRules).Text("Revision") == "1.0.0", "remote rule revisions overwritten");
        sets.SelectVersion(rule.Text("Id"), oldRules.Text("Current"), ArchiveStore.Fingerprint(newer)); Check(ServerRuleSetStore.Current(sets.Read(rule.Text("Id"))).Text("Revision") == "1.0.0", "rule history selection failed");
        var pinned = Definition("RuleSet"); pinned["ExpectedSha256"] = new string('a', 64); manager.Register(pinned); await RefusesAsync(() => manager.FetchAsync(pinned.Text("Id"), default), "pinned digest mismatch accepted");
        rule["Rules"]![0]!["Script"] = "unsafe"; fetch.Content = rule.ToJsonString(); await RefusesAsync(() => manager.FetchAsync(ruleId, default), "remote rule script accepted");
    }
}
internal sealed class Remote43Fetch : IClientSourceFetch
{
    public string Content { get; set; } = "";
    public Task<string> FetchAsync(JsonObject source, CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.FromResult(Content); }
}
