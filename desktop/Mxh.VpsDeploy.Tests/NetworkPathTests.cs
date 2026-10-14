using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task NetworkPathExperience(Fixture f, JsonObject original)
    {
        JsonObject Copy() => original.DeepClone().AsObject();
        JsonObject Analyze(JsonObject report) { report["Analysis"] = NetworkTuning.Analyze(report); return report; }
        var noScoped = Copy(); noScoped["Client"]!.AsObject().Remove("EvidencePolicy");
        Check(Analyze(noScoped).Text("Analysis.Profile") == "EntryBasic", "legacy global counters offered scoped tuning");
        var noLimit = Copy(); foreach (var t in noLimit["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["TcpEvidence"]!["SendBufferLimitedPercent"] = 0;
        Check(Analyze(noLimit).Long("Analysis.BufferTargetBytes") == 0, "unproven buffer limit produced global candidate");
        var singlePeer = Copy(); singlePeer["Client"]!["Transfers"] = new JsonArray(singlePeer["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>().Where(t => t.Text("Endpoint") != "Hetzner").Select(t => t.DeepClone()).ToArray());
        Check(Analyze(singlePeer).Text("Analysis.Profile") == "EntryBasic", "one abnormal peer derived global settings");
        var mixedTraffic = Copy(); foreach (var t in mixedTraffic["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["TcpEvidence"]!["PayloadMatched"] = false;
        Check(!NetworkTuning.LossEvidence(mixedTraffic).Flag("Eligible") && Analyze(mixedTraffic).Text("Analysis.Profile") == "EntryBasic", "unmatched background traffic became measurement evidence");
        var missingStart = Copy(); missingStart["Client"]!["Startup"] = new JsonArray();
        Check(Analyze(missingStart).Text("Analysis.Profile") == "EntryBasic", "short connection guard missing");
        var queue = Copy(); queue["Client"]!["LoadedLatencyMs"] = new JsonArray(300, 300, 300);
        Check(Analyze(queue).Long("Analysis.BufferTargetBytes") == 0, "queue inflation expanded buffers");
        var global = Copy(); global["ServerAfter"]!["Counters"] = new JsonObject { ["TcpRetransSegs"] = 999999999, ["TcpOutSegs"] = 0 };
        Check(NetworkTuning.LossEvidence(global).Flag("Eligible") && NetworkTuning.LossEvidence(global).Text("Scope") == "MatchedTcpSockets", "unrelated global counters affected directional evidence");
        var landingDiagnostic = Copy(); landingDiagnostic["Options"]!["Topology"] = "Landing";
        Check(Analyze(landingDiagnostic).Text("Analysis.Profile") == "LandingBasic", "landing diagnostic offered fine tuning");
        var forward = Copy(); forward["Options"]!["Topology"] = "ForwardOnly";
        Check(Analyze(forward).Long("Analysis.BufferTargetBytes") == 0, "forwarded TCP treated as local congestion-controlled socket");
        var uploadOnly = Copy(); uploadOnly["Options"]!["PriorityDirection"] = "Upload";
        Check(Analyze(uploadOnly).Text("Analysis.Profile") == "EntryBasic", "single public upload peer offered global fine tuning");
        var baseline = Analyze(Copy());
        var faster = Copy(); foreach (var t in faster["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["Mbps"] = 140;
        Analyze(faster);
        Check(NetworkTuning.Compare(baseline, faster) == "Improved", "multiple independent repeated gains rejected");
        var slowStart = faster.DeepClone().AsObject(); foreach (var t in slowStart["Client"]!["Startup"]!.AsArray().OfType<JsonObject>()) if (t.Text("Endpoint") == "Hetzner") t["Milliseconds"] = 200;
        Analyze(slowStart); Check(NetworkTuning.CompareDetailed(baseline, slowStart).Text("ReasonCode") == "ShortConnectionRegression", "faster long flows hid slower webpage start");
        var masked = faster.DeepClone().AsObject(); foreach (var t in masked["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Endpoint") == "Hetzner") t["TcpEvidence"]!["RetransmittedSegments"] = 200;
        Analyze(masked); Check(NetworkTuning.Compare(baseline, masked) == "Regression", "good peer hid another peer's loss regression");
        var uploadGain = Copy(); foreach (var t in uploadGain["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Upload") t["Mbps"] = 200;
        Analyze(uploadGain); Check(NetworkTuning.Compare(baseline, uploadGain) == "NoClearGain", "opposite-direction speed substituted priority goal");
        var oneFaster = Copy(); foreach (var t in oneFaster["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Endpoint") == "Cloudflare") t["Mbps"] = 200;
        Analyze(oneFaster); Check(NetworkTuning.Compare(baseline, oneFaster) == "NoClearGain", "one endpoint's speed promoted global gain");
        var oneLessLoss = Copy(); foreach (var t in oneLessLoss["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Endpoint") == "Hetzner") t["TcpEvidence"]!["RetransmittedSegments"] = 10;
        Analyze(oneLessLoss); Check(NetworkTuning.CompareDetailed(baseline, oneLessLoss).Text("ReasonCode") == "LossGainNotRepeated", "one endpoint's loss anomaly drove global candidate retention");
        var hiddenSlowdown = Copy(); foreach (var t in hiddenSlowdown["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) { t["TcpEvidence"]!["RetransmittedSegments"] = 10; t["Mbps"] = t.Text("Endpoint") == "Cloudflare" ? 50 : 150; }
        Analyze(hiddenSlowdown); Check(NetworkTuning.Compare(baseline, hiddenSlowdown) == "Tradeoff", "combined median hid severe slowdown of one peer");
        var noLoaded = faster.DeepClone().AsObject(); noLoaded["Client"]!["LoadedLatencyMs"] = new JsonArray(); Analyze(noLoaded);
        Check(NetworkTuning.Compare(baseline, noLoaded) == "Inconclusive", "missing queue evidence was treated as zero latency");
        var duplicateStart = faster.DeepClone().AsObject(); duplicateStart["Client"]!["Startup"]!.AsArray().Add(duplicateStart["Client"]!["Startup"]![0]!.DeepClone());
        Check(NetworkTuning.CompareDetailed(baseline, duplicateStart).Text("ReasonCode") == "DuplicateStartupSamples", "duplicate startup round accepted");
        var changedPath = faster.DeepClone().AsObject(); changedPath["PathFingerprint"] = "other";
        Check(NetworkTuning.Compare(baseline, changedPath) == "Inconclusive", "different relay endpoints compared");
        JsonObject Point(long sent, long retrans, string identity = "cookie", string boot = "boot") => new() { ["BootId"] = boot, ["Tcp"] = new JsonObject { ["Sockets"] = new JsonArray(new JsonObject { ["Identity"] = identity, ["Leg"] = "ToUser", ["DataSegmentsOut"] = sent, ["TotalRetrans"] = retrans, ["BytesSent"] = sent * 1000, ["RttMs"] = 80, ["BusyMs"] = sent / 10, ["SendBufferLimitedMs"] = sent / 50 }) } };
        var evidence = NetworkTuning.SocketEvidence([Point(1000, 10), Point(3000, 12)], "ToUser");
        Check(evidence.Flag("CountersValid") && evidence.Long("SentSegments") == 2000 && evidence.Long("RetransmittedSegments") == 2, "socket counters were not differenced");
        Check(evidence.Flag("ByteCoverageKnown") && evidence.Long("BytesSent") == 2000000 && NetworkTuning.Value(evidence, "SendBufferLimitedPercent") == 20, "socket payload or send limit used lifetime totals");
        Check(!NetworkTuning.SocketEvidence([Point(1000, 10), Point(3000, 12, "new-cookie")], "ToUser").Flag("CountersValid"), "reused tuple counted as same socket");
        Check(!NetworkTuning.SocketEvidence([Point(3000, 12), Point(1000, 10)], "ToUser").Flag("CountersValid"), "socket reset accepted");
        Check(!NetworkTuning.SocketEvidence([Point(1000, 10), Point(3000, 12, boot: "new-boot")], "ToUser").Flag("CountersValid"), "socket counters crossed a reboot");
        Check(!NetworkTuning.SocketEvidence([Point(1000, 10), Point(3000, 12)], "ToNextHop").Flag("CountersValid"), "opposite TCP leg contaminated evidence");
        var unknown = Point(3000, 12); unknown["Tcp"]!["Sockets"]![0]!.AsObject().Remove("TotalRetrans");
        Check(!NetworkTuning.SocketEvidence([Point(1000, 10), unknown], "ToUser").Flag("CountersValid"), "missing socket retransmissions became zero");
        var truncated = Point(3000, 12); truncated["Tcp"]!["Truncated"] = true;
        Check(!NetworkTuning.SocketEvidence([Point(1000, 10), truncated], "ToUser").Flag("CountersValid"), "truncated socket list provided fine evidence");
        var retriesOnly = NetworkTuning.SocketEvidence([Point(1000, 10), Point(1000, 20)], "ToUser");
        Check(retriesOnly.Long("RetransmittedSegments") == 10 && retriesOnly.Long("SentSegments") == 0, "retry-only socket silently erased lost data");

        var plan = f.Plan("RelaySource"); f.SaveInstance(plan);
        var peer = f.Plan("RelayDestination"); peer["Role"] = "ShadowsocksLanding"; peer["Roles"] = new JsonArray("ShadowsocksLanding");
        peer.Put("Server.IPv4", JsonValue.Create("192.0.2.20")); peer.Put("Ports.LandingShadowsocks", JsonValue.Create(4000)); peer.Put("Shadowsocks.Method", JsonValue.Create("2022-blake3-aes-128-gcm"));
        peer["ProtocolInventory"] = new JsonObject { ["ShadowsocksLanding"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true } }; f.SaveInstance(peer);
        var peerDir = f.Paths.Instance(f.Relative(peer)); var peerState = ArchiveStore.ReadJson(SafePath.Resolve(peerDir, "deployment-state.json")); peerState["DeploymentTransaction"] = new JsonObject { ["Status"] = "Committed" }; ArchiveStore.WriteJson(SafePath.Resolve(peerDir, "deployment-state.json"), peerState);
        f.Store.WriteSecret(SafePath.Resolve(peerDir, "secrets.dotnet.private.json"), new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = "fixture-server", ["PrimaryUserKey"] = "fixture-user" } });
        var relayOptions = NetworkTuning.Defaults(plan); relayOptions["Topology"] = "Relay"; relayOptions["PeerInstance"] = f.Relative(peer);
        using (var route = NetworkTuning.ResolvePath(f.Store, plan, Fixture.RealitySecrets(), relayOptions, f.Relative(plan)))
        {
            var config = ClientProfiles.SingProbe(route.Node, 12345, route.Entry);
            Check(route.ExpectedEgress == "192.0.2.20" && route.Entry != null && config["outbounds"]![0]!.Text("detour") == "mxh-probe-entry", "relay measurement bypassed actual entry-to-landing leg");
        }
        peer.Put("Server.IPv6", JsonValue.Create("2001:db8::20")); peer.Put("Shadowsocks.SecondaryIpv6Enabled", JsonValue.Create(true)); peer.Put("Shadowsocks.SecondaryIpv6Address", JsonValue.Create("2001:db8:1::20"));
        ArchiveStore.WriteJson(SafePath.Resolve(peerDir, "deployment-plan.json"), peer); relayOptions["PeerEgress"] = "IPv6";
        using (var route = NetworkTuning.ResolvePath(f.Store, plan, Fixture.RealitySecrets(), relayOptions, f.Relative(plan))) Check(route.ExpectedEgress == "2001:db8:1::20" && route.Node.Family == "IPv4", "IPv6 dedicated egress confused with native listener address");
        var directOptions = NetworkTuning.Defaults(peer); directOptions["PeerEgress"] = "IPv6";
        using (var route = NetworkTuning.ResolvePath(f.Store, peer, new JsonObject(), directOptions, f.Relative(peer))) Check(route.ExpectedEgress == "2001:db8:1::20" && route.Entry == null, "landing diagnostic ignored the selected IPv6 source");
        relayOptions["PeerEgress"] = "IPv4";
        var peerHash = NetworkTuning.PeerArchiveFingerprint(f.Store, relayOptions);
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed)));
        var request = new OperationRequest(OperationKind.MeasureNetwork, f.Relative(plan), relayOptions); var review = coordinator.Review(request);
        peer.Put("Server.IPv4", JsonValue.Create("192.0.2.21")); ArchiveStore.WriteJson(SafePath.Resolve(peerDir, "deployment-plan.json"), peer);
        Check(NetworkTuning.PeerArchiveFingerprint(f.Store, relayOptions) != peerHash, "scheduled peer change was invisible");
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "peer changed after review but test still ran");
        relayOptions["PeerInstance"] = f.Relative(plan);
        Refuses(() => NetworkTuning.ResolvePath(f.Store, plan, Fixture.RealitySecrets(), relayOptions, f.Relative(plan)), "relay selected itself");
        relayOptions["PeerInstance"] = "../external"; Refuses(() => NetworkTuning.ValidateMeasurement(relayOptions), "relay escaped archive boundary");
        var remote = new FakeRemote(); var adapter = new FakeNetwork(); var options = NetworkTuning.Defaults(plan); options["Topology"] = "ForwardOnly";
        await new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), adapter).ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(plan), options), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(adapter.Calls == 0 && remote.Mutations == 0, "forward-only diagnostic launched irrelevant saturation tests");
    }
}
