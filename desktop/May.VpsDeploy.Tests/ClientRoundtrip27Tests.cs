using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private static readonly string Link27Uuid=Guid.NewGuid().ToString();
    private static string Link27(string protocol,string host="entry.example.test",int port=443,string mode="native",string congestion="cubic")=>protocol+"://"+(protocol=="vless"?Link27Uuid:protocol=="tuic"?Link27Uuid+":":"")+(protocol=="vless"?"":"synthetic%3Ap%40ss%2B%25")+"@"+(host.Contains(':')?"["+host+"]":host)+":"+port+"?sni=stream.example.test"+(protocol=="tuic"?"&allow_insecure=0&congestion_control="+congestion+"&udp_relay_mode="+mode+"&alpn=h3":"&security=tls&type=tcp&alpn=http%2F1.1"+(protocol=="vless"?"&encryption=none":""))+"#Round27-"+protocol;
    public async Task RunClientRoundtrip27Tests(bool modelOnly=false)
    {
        await ClientRoundtrip27Model();if(!modelOnly)await ClientRoundtrip27Runtime();Console.WriteLine($"PASS: {assertions} round-27 share/import, native client outputs and path assertions; modelOnly={modelOnly}.");
    }
    private async Task ClientRoundtrip27Model()
    {
        using var f=new Fixture(repository);var scheme=ClientSchemes.New(f.Paths);var region=scheme["Layout"]!.Strings("region_groups")[0];
        var links=new[]{Link27("vless"),Link27("trojan"),Link27("tuic"),Link27("tuic","2001:db8::27",8443,"quic","bbr").Replace("#Round27-tuic","#IPv6-中文")};
        var input=string.Join("\r\n",links)+"\r\n";var before=ArchiveStore.Fingerprint(scheme);var preview=ClientNodeImport.Preview(input,scheme,region,"entry");Check(preview.Accepted==4&&before==ArchiveStore.Fingerprint(scheme),"round27 preview rejected existing protocol or mutated source: "+string.Join(";",preview.Rows.Select(r=>r.Message)));ClientNodeImport.Apply(scheme,preview);
        var nodes=scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        foreach(var format in new[]{"Plain","Base64"})
        {
            var share=ClientShareLinks.Preview(scheme);Check(share.Rows.All(r=>r.Ready),"simple link sharing refused: "+string.Join(';',share.Rows.Select(r=>r.Message)));var text=ClientShareLinks.Generate(scheme,share,share.Rows.Select(r=>r.Id).ToArray(),format);var parsed=ClientNodeImport.Preview(text,ClientSchemes.New(f.Paths),region,"entry");Check(parsed.Accepted==4,"own share list cannot be imported directly");
            foreach(var(a,b)in nodes.Zip(parsed.Rows.Select(r=>r.Node!)))Check(ClientNodeImport.ConnectionFingerprint(a)==ClientNodeImport.ConnectionFingerprint(b),"share roundtrip lost protocol data");
        }
        foreach(var source in nodes)
        {
            foreach(var keep in new[]{"clash","sing_box"}){var one=ClientSchemes.New(f.Paths);var n=source.DeepClone().AsObject();n.Remove(keep=="clash"?"sing_box":"clash");one["Nodes"]=new JsonArray(n);Check(ClientShareLinks.Preview(one).Rows.Single().Ready,"single-client node was not shareable");}
        }
        foreach(var bad in new[]{Link27("tuic").Replace(Link27Uuid,"old-token"),Link27("tuic").Replace("allow_insecure=0","allow_insecure=1"),Link27("tuic")+"\n"+Link27("tuic").Replace("&alpn=h3","&heartbeat=20s"),Link27("vless").Replace("security=tls","security=none"),Link27("trojan").Replace("&type=tcp","&type=tcp&path=%2Fws"),Link27("vless").Replace("&encryption=none","&encryption=none&flow=xtls-rprx-vision")})
        {
            var result=ClientNodeImport.Preview(bad,ClientSchemes.New(f.Paths),region,"entry");Check(result.Rows.Any(r=>r.Status=="Rejected")&&result.Rows.All(r=>!r.Message.Contains("synthetic")&&!r.Message.Contains(Link27Uuid)),"unsupported parameter dropped or error leaked credentials");
        }
        foreach(var edit in new Action<JsonObject>[] {n=>n["sing_box"]!["heartbeat"]="20s",n=>n["clash"]!["reduce-rtt"]=true,n=>n["sing_box"]!["tls"]!["certificate_path"]="private.pem",n=>n["clash"]!["password"]="other-synthetic"})
        {var one=ClientSchemes.New(f.Paths);var n=nodes[2].DeepClone().AsObject();edit(n);one["Nodes"]=new JsonArray(n);Check(!ClientShareLinks.Preview(one).Rows.Single().Ready,"TUIC lossy or inconsistent pair was shared");}
        var maximum=ClientSchemes.New(f.Paths);for(var i=0;i<200;i++){var n=nodes[1].DeepClone().AsObject();n["Id"]=Guid.NewGuid().ToString("N");n["sing_box"]!["server_port"]=20000+i;n["clash"]!["port"]=20000+i;n["name"]="中文节点-"+i;n["sing_box"]!["tag"]=n.Text("name");n["clash"]!["name"]=n.Text("name");maximum["Nodes"]!.AsArray().Add(n);}
        foreach(var format in new[]{"Plain","Base64"}){var p=ClientShareLinks.Preview(maximum);var text=ClientShareLinks.Generate(maximum,p,p.Rows.Select(r=>r.Id).ToArray(),format);Check(ClientNodeImport.Preview(text,ClientSchemes.New(f.Paths),region,"entry").Accepted==200,"200-node list rejected its own trailing newline or base64");}
        var longList=ClientSchemes.New(f.Paths);for(var i=0;i<70;i++){var n=nodes[1].DeepClone().AsObject();n["Id"]=Guid.NewGuid().ToString("N");n["sing_box"]!["password"]=new string('s',3000)+i;n["clash"]!["password"]=n["sing_box"]!["password"]!.DeepClone();longList["Nodes"]!.AsArray().Add(n);}var longPreview=ClientShareLinks.Preview(longList);var encoded=ClientShareLinks.Generate(longList,longPreview,longPreview.Rows.Select(r=>r.Id).ToArray(),"Base64");Check(encoded.Length>ClientNodeImport.MaximumCharacters&&ClientNodeImport.Preview(encoded,ClientSchemes.New(f.Paths),region,"entry").Accepted==70,"encoded wrapper rejected a bounded decoded list");
        Refuses(()=>ClientNodeImport.Preview(new string('a',ClientNodeImport.MaximumInputCharacters+1),scheme,region),"unbounded encoded input accepted");Refuses(()=>ClientNodeImport.Preview(string.Join('\n',Enumerable.Repeat(links[0],201)),scheme,region),"201-node input accepted");
        workbench(f).Save(scheme);var tx=Guid.NewGuid().ToString("N");var transaction=f.Paths.Resolve("private/client-source-sync/transactions/"+tx+".dotnet.private.json");f.Store.WriteSecret(transaction,new JsonObject{["Schema"]=1,["Id"]=tx,["Phase"]="Applying",["Items"]=new JsonArray(new JsonObject{["Kind"]="Scheme",["Id"]=scheme.Text("Id"),["Before"]=scheme.DeepClone(),["After"]=scheme.DeepClone()})});var blocked=ClientShareLinks.Preview(scheme);Refuses(()=>new ClientShareExport(f.Store).Generate(scheme,blocked,blocked.Rows.Select(r=>r.Id).ToArray(),"Plain"),"share bypassed pending source synchronization");File.Delete(transaction);
        if(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is {} python)
        {
            var bench=new ClientWorkbench(f.Store,new ExternalToolRunner(),new ValidationAssets(new AppPaths(repository),"windows-amd64"),python);await bench.BuildAsync(scheme,default);await bench.ValidateAsync(scheme,default);Check(scheme.Text("Candidate.ValidationStatus")=="Passed","round27 outputs did not pass both pinned cores");
            foreach(var formats in new[]{"Both","Clash","SingBox"}){var read=await bench.ReadSourcesAsync(formats=="SingBox"?"":scheme.Text("Candidate.Clash"),formats=="Clash"?"":scheme.Text("Candidate.SingBox"),default);Check(read.Count==4,"native output reimport lost protocols");foreach(var n in read.OfType<JsonObject>()){var original=nodes.Single(a=>a.Text("name")==n.Text("name"));foreach(var field in formats=="Both"?new[]{"clash","sing_box"}:new[]{formats=="Clash"?"clash":"sing_box"})Check(JsonNode.DeepEquals(n[field],original[field]),"native output/reimport altered connection parameters");}}
        }
        ClientWorkbench workbench(Fixture fixture)=>new(fixture.Store,new ExternalToolRunner(),new ValidationAssets(new AppPaths(repository),"windows-amd64"),Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python");
    }
}
