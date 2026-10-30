using System.Text.Json;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ClientNodeImport
{
    private static JsonObject ParseXhttp(string name,string host,int port,string auth,Dictionary<string,string> q)
    {
        RequireKeys(q,["security","type","encryption","flow","sni","fp","alpn","path","host","mode","extra","pbk","sid"]);
        if(q.GetValueOrDefault("encryption","none")!="none"||q.GetValueOrDefault("flow","")!=""||q.GetValueOrDefault("security") is not ("tls" or "reality"))throw new OperationException("XHTTP 链接需要 TLS／Reality、空 flow 和 encryption=none。");
        var tls=new JsonObject{["enabled"]=true,["server_name"]=q.GetValueOrDefault("sni",host)};
        if(q.TryGetValue("fp",out var fp))tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=fp};
        if(q.TryGetValue("alpn",out var alpn))tls["alpn"]=new JsonArray(alpn.Split(',').Select(a=>(JsonNode?)JsonValue.Create(a)).ToArray());
        if(q["security"]=="reality"){tls["reality"]=new JsonObject{["enabled"]=true,["public_key"]=q.GetValueOrDefault("pbk",""),["short_id"]=q.GetValueOrDefault("sid","")};if(tls["utls"]==null)tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]="chrome"};}
        else if(q.ContainsKey("pbk")||q.ContainsKey("sid"))throw new OperationException("TLS XHTTP 不应包含 Reality 身份字段。");
        var t=new JsonObject{["type"]="xhttp",["path"]=q.GetValueOrDefault("path","/"),["host"]=q.GetValueOrDefault("host",""),["mode"]=q.GetValueOrDefault("mode","auto")};
        if(q.TryGetValue("extra",out var raw))
        {
            JsonObject extra;try{extra=JsonNode.Parse(raw) as JsonObject??throw new JsonException();}catch(JsonException){throw new OperationException("XHTTP extra 须为完整 JSON 对象。");}
            if(extra["downloadSettings"] is JsonObject down){t["download_settings"]=VlessXhttp.DownloadFromXray(down);extra.Remove("downloadSettings");}else if(extra.ContainsKey("downloadSettings"))throw new OperationException("XHTTP downloadSettings 须为对象。");
            t["extra"]=extra;
        }
        var n=VlessXhttp.CanonicalNative(new JsonObject{["type"]="vless",["tag"]=name,["server"]=host,["server_port"]=port,["uuid"]=auth,["packet_encoding"]="xudp",["tls"]=tls,["transport"]=t},name);
        var node=new JsonObject{["name"]=name,["sing_box"]=n,["clash"]=null};VlessXhttp.CompletePair(node);return node;
    }
}
