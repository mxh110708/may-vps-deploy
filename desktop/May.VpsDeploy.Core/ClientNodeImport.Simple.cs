using System.Text.Json.Nodes;
namespace May.VpsDeploy.Core;
public static partial class ClientNodeImport
{
    private static JsonObject ParseTuic(string name,string host,int port,string auth,Dictionary<string,string> query)
    {
        RequireKeys(query,["sni","alpn","congestion_control","udp_relay_mode","allow_insecure"]);
        if(query.GetValueOrDefault("allow_insecure","0")!="0")throw new OperationException("TUIC 链接须保留 TLS 验证。");var split=auth.IndexOf(':');if(split<1)throw new OperationException("TUIC v5 需要 UUID 和密码，不接受 v4 Token。");
        var n=new JsonObject{["type"]="tuic",["tag"]=name,["server"]=host,["server_port"]=port,["uuid"]=auth[..split],["password"]=auth[(split+1)..],["congestion_control"]=query.GetValueOrDefault("congestion_control","cubic"),["udp_relay_mode"]=query.GetValueOrDefault("udp_relay_mode","native"),["tls"]=LinkTls(host,query)};
        return SimplePair(n,name);
    }
    private static JsonObject ParseTlsTcp(string protocol,string name,string host,int port,string auth,Dictionary<string,string> query)
    {
        RequireKeys(query,protocol=="vless"?["security","type","encryption","flow","sni","fp","alpn"]:["security","type","sni","fp","alpn"]);
        if(query.GetValueOrDefault("security",protocol=="trojan"?"tls":"")!="tls"||query.GetValueOrDefault("encryption","none")!="none"||query.GetValueOrDefault("flow","")!="")throw new OperationException("普通 TCP 分享仅接受可验证的 TLS，不接受明文或 Vision flow。");
        var n=new JsonObject{["type"]=protocol,["tag"]=name,["server"]=host,["server_port"]=port,[protocol=="vless"?"uuid":"password"]=auth,["tls"]=LinkTls(host,query)};
        return SimplePair(n,name);
    }
    private static JsonObject LinkTls(string host,Dictionary<string,string> query)
    {
        var tls=new JsonObject{["enabled"]=true,["server_name"]=query.GetValueOrDefault("sni",host)};
        if(query.TryGetValue("alpn",out var a))tls["alpn"]=new JsonArray(a.Split(',').Select(s=>(JsonNode?)JsonValue.Create(s)).ToArray());if(query.TryGetValue("fp",out var fp))tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=fp};return tls;
    }
    private static JsonObject SimplePair(JsonObject n,string name)
    {
        var native=ClientSimpleLinks.Canonical(n,name);return new(){["name"]=name,["sing_box"]=native,["clash"]=ClientSimpleLinks.ToClash(native,name)};
    }
}
