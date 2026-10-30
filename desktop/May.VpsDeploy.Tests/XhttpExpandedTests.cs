using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void XhttpExpandedModel()
    {
        using var f=new Fixture(repository);
        JsonObject Node(string mode,string version,JsonObject extra)
        {
            var options=VlessXhttp.Options();options["ServerName"]="identity.example.test";options["Transport"]!["Path"]="/literal%2Fpath/?keep=a%2Fb";options["Transport"]!["Host"]="front.example.test:443";options["Transport"]!["Mode"]=mode;options["Transport"]!["HTTPVersion"]=version;options["Transport"]!["Extra"]=extra.DeepClone();
            var native=VlessXhttp.Native("Synthetic-XHTTP","entry.example.test",443,Guid.NewGuid().ToString(),options);
            return new JsonObject{["Id"]=Guid.NewGuid().ToString("N"),["name"]="Synthetic-XHTTP",["kind"]="entry",["region_group"]="US-West-LA Entry",["transit_group"]="US-West-LA Entry",["sing_box"]=native,["clash"]=VlessXhttp.ToClash(native,"Synthetic-XHTTP")};
        }
        var extra=new JsonObject{["xPaddingObfsMode"]=true,["xPaddingPlacement"]="cookie",["xPaddingMethod"]="tokenish",["xPaddingKey"]="may-padding",["sessionPlacement"]="header",["sessionKey"]="X-May-Session",["seqPlacement"]="query",["seqKey"]="may_seq",["scMaxEachPostBytes"]="2048-4096",["scMinPostsIntervalMs"]=5,["xmux"]=new JsonObject{["maxConnections"]=2,["hMaxRequestTimes"]="10-20",["hMaxReusableSecs"]="60-120",["hKeepAlivePeriod"]=-1}};
        foreach(var mode in new[]{"auto","stream-one","stream-up","packet-up"})foreach(var version in new[]{"1.1","2","3"})
        {
            var node=Node(mode,version,extra);var fingerprint=ClientNodeImport.ConnectionFingerprint(node);var link=VlessXhttp.ShareLink(node);var scheme=ClientSchemes.New(f.Paths);var parsed=ClientNodeImport.Preview(link,scheme,"US-West-LA Entry");Check(parsed.Accepted==1,"expanded XHTTP URI rejected");var imported=parsed.Rows.Single().Node!;
            Check(ArchiveStore.Fingerprint(VlessXhttp.RequireNative(imported))==ArchiveStore.Fingerprint(VlessXhttp.RequireNative(node)),"XHTTP link lost mode/version/query/extra");Check(ClientNodeImport.ConnectionFingerprint(node)==fingerprint,"sharing mutated source identity");
            var definition=ClientSubscriptions.New("US-West-LA Entry");definition["Url"]="https://subscription.example.test/private";var preview=ClientSubscriptions.Preview(scheme,definition,link);Check(preview.Ready,"XHTTP subscription preview failed");ClientSubscriptions.Apply(scheme,preview);Check(scheme["Nodes"]!.AsArray().Count==1,"subscription omitted XHTTP");
        }
        var split=Node("packet-up","2",extra);var n=split["sing_box"]!.AsObject();var down=n.DeepClone().AsObject();down["server"]="download.example.test";down["server_port"]=8443;down["tls"]!["server_name"]="download-identity.example.test";down["transport"]!["host"]="down.example.test";down["transport"]!["path"]="/download/?keep=%2F";down["transport"]!["extra"]!["sessionPlacement"]="cookie";down["transport"]!["extra"]!["sessionKey"]="sid";
        n["transport"]!["download_settings"]=new JsonObject{["server"]=down["server"]!.DeepClone(),["server_port"]=down["server_port"]!.DeepClone(),["tls"]=down["tls"]!.DeepClone(),["transport"]=down["transport"]!.DeepClone()};split["clash"]=null;
        Refuses(()=>VlessXhttp.ToClash(n,split.Text("name")),"Mihomo independent download metadata was silently dropped");var splitLink=VlessXhttp.ShareLink(split);Check(splitLink.Contains("downloadSettings"),"XHTTP share lost independent download");
        var before=ClientNodeImport.ConnectionFingerprint(split);n["transport"]!["download_settings"]!["tls"]!["server_name"]="changed.example.test";Check(before!=ClientNodeImport.ConnectionFingerprint(split),"download TLS identity missing from fingerprint");
        foreach(var mutation in new Action<JsonObject>[] { x=>x["unknown"]=true,x=>x["headers"]=new JsonObject{["Host"]="other.example.test"},x=>x["xmux"]=new JsonObject{["maxConcurrency"]=1,["maxConnections"]=2},x=>x["sessionPlacement"]="unknown",x=>x["scMaxEachPostBytes"]="10-1" }){var invalid=extra.DeepClone().AsObject();mutation(invalid);Refuses(()=>VlessXhttp.ValidateExtra(invalid),"invalid extra survived review");}
        var reality=Node("stream-one","3",new());reality["sing_box"]!["tls"]!["reality"]=new JsonObject{["enabled"]=true,["public_key"]=new string('A',43),["short_id"]="abcd1234"};reality["clash"]=null;Refuses(()=>VlessXhttp.RequireNative(reality),"Reality HTTP/3 was accepted");
        foreach(var shortId in new[]{"ABCD1234",""}){var r=Node("auto","2",new());r["clash"]=null;r["sing_box"]!["tls"]!["reality"]=new JsonObject{["enabled"]=true,["public_key"]=new string('A',43),["short_id"]=shortId};r["sing_box"]!["tls"]!["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]="chrome"};Check(VlessXhttp.RequireNative(r).Text("tls.reality.short_id")==shortId.ToLowerInvariant(),"valid Reality client short ID was rejected or changed semantically");_=VlessXhttp.ShareLink(r);}
        var inconsistent=Node("stream-up","2",extra);inconsistent["clash"]!["xhttp-opts"]!["path"]="/different/";Refuses(()=>VlessXhttp.RequireNative(inconsistent),"conflicting pair selected one client silently");
        var mihomoOnly=Node("stream-up","2",extra);mihomoOnly["sing_box"]=null;mihomoOnly["clash"]!["xhttp-opts"]!["session-table"]="0123456789abcdef";mihomoOnly["clash"]!["xhttp-opts"]!["session-length"]="16-24";
        VlessXhttp.CompletePair(mihomoOnly);Check(mihomoOnly["sing_box"]==null,"Mihomo-only session extension fabricated a May native config");Refuses(()=>VlessXhttp.RequireNative(mihomoOnly),"Mihomo session extension converted lossily");
        var mixed=ClientSchemes.New(f.Paths);mixed["Nodes"]=new JsonArray(mihomoOnly);var capabilities=ClientCapabilities.Inspect(mixed);Check(capabilities.Single(c=>c.Client=="Clash").Ready&&!capabilities.Single(c=>c.Client=="SingBox").Ready,"missing native source was advertised ready");
    }
}
