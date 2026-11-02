using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

// URI projections for existing protocols. Unknown native fields must use full
// client configuration export; this class never silently trims them for sharing.
public static class ClientSimpleLinks
{
    public static bool IsNative(JsonObject n)=>n.Text("type")=="tuic"||n.Text("type") is "vless" or "trojan"&&n["transport"]==null&&n.At("tls.reality")==null;
    public static bool IsClash(JsonObject n)=>n.Text("type")=="tuic"||n.Text("type") is "vless" or "trojan"&&n.Text("network") is "" or "tcp" or "raw"&&n["reality-opts"]==null;
    public static bool IsNode(JsonObject n)=>n["sing_box"] is JsonObject s&&IsNative(s)||n["clash"] is JsonObject c&&IsClash(c);
    private static void Fields(JsonObject o,params string[] keys){if(o.Any(p=>!keys.Contains(p.Key,StringComparer.Ordinal)))throw new OperationException("连接含链接无法完整表达的高级参数，请导出完整客户端配置。");}
    private static string S(JsonObject o,string key,string fallback="")=>o[key]==null&&!o.ContainsKey(key)?fallback:o[key] is JsonValue v&&v.TryGetValue<string>(out var s)?s:throw new OperationException("连接文本参数类型无效。");
    private static bool B(JsonObject o,string key,bool fallback=false)=>!o.ContainsKey(key)?fallback:o[key] is JsonValue v&&v.TryGetValue<bool>(out var b)?b:throw new OperationException("连接开关类型无效。");
    private static int I(JsonObject o,string key,int fallback=0)=>!o.ContainsKey(key)?fallback:o[key] is JsonValue v&&v.TryGetValue<int>(out var i)?i:throw new OperationException("连接数值参数类型无效。");
    private static string Host(string s)
    {
        if(s.Length is <1 or >253||s.Any(char.IsControl)||s.Contains('%')||Uri.CheckHostName(s)==UriHostNameType.Unknown)throw new OperationException("服务器地址或 TLS 名称无效。");
        return IPAddress.TryParse(s,out var ip)?ip.ToString():new IdnMapping().GetAscii(s).ToLowerInvariant();
    }
    private static string Password(JsonObject o){var s=S(o,"password");if(s.Length is <1 or >4096||s.Any(char.IsControl))throw new OperationException("连接密码缺失或无效。");return s;}
    public static JsonObject Canonical(JsonObject n,string name)
    {
        var protocol=S(n,"type");var tuic=protocol=="tuic";
        if(!tuic&&protocol is not ("vless" or "trojan"))throw new OperationException("此链接投影仅用于 TUIC v5 或普通 TLS 的 VLESS／Trojan。");
        Fields(n,new[]{"type","tag","server","server_port","tls",protocol=="trojan"?"password":"uuid"}.Concat(tuic?["password","congestion_control","udp_relay_mode","heartbeat","zero_rtt_handshake"]:protocol=="vless"?["flow","packet_encoding"]:Array.Empty<string>()).ToArray());
        var port=I(n,"server_port");if(S(n,"tag")!=name||port is <1 or >65535||name.Length is <1 or >120||name.Any(char.IsControl))throw new OperationException("节点名称或端口无效。");
        var result=new JsonObject{["type"]=protocol,["tag"]=name,["server"]=Host(S(n,"server")),["server_port"]=port};
        if(protocol!="trojan"){if(!Guid.TryParseExact(S(n,"uuid"),"D",out var uuid)||uuid==Guid.Empty)throw new OperationException("UUID 无效；TUIC v4 Token 不属于此格式。");result["uuid"]=uuid.ToString();}
        if(protocol!="vless")result["password"]=Password(n);
        if(protocol=="vless"){if(S(n,"flow")!=""||S(n,"packet_encoding","xudp")!="xudp")throw new OperationException("普通 TLS VLESS 不接受 Vision 或不可表达的 UDP 编码。");result["packet_encoding"]="xudp";}
        var tls=n["tls"] as JsonObject??throw new OperationException("连接需要完整可验证的 TLS。");
        Fields(tls,tuic?["enabled","server_name","insecure","alpn","min_version"]:["enabled","server_name","insecure","alpn","utls"]);
        if(!B(tls,"enabled")||B(tls,"insecure")||tuic&&S(tls,"min_version") is not ("" or "1.3"))throw new OperationException("链接必须保留 TLS 证书验证，TUIC 使用 TLS 1.3。");
        var outputTls=new JsonObject{["enabled"]=true,["server_name"]=Host(S(tls,"server_name",result.Text("server")))};result["tls"]=outputTls;
        if(tls.ContainsKey("alpn"))
        {
            if(tls["alpn"] is not JsonArray {Count:>0 and <=16} alpn||alpn.Any(a=>a is not JsonValue v||!v.TryGetValue<string>(out var s)||s.Length is <1 or >32||s.Contains(',')||s.Any(char.IsControl)))throw new OperationException("ALPN 列表无法完整表达。");outputTls["alpn"]=tls["alpn"]!.DeepClone();
        }
        if(tls.ContainsKey("utls"))
        {
            if(tls["utls"] is not JsonObject u)throw new OperationException("TLS 指纹字段无效。");Fields(u,"enabled","fingerprint");if(!B(u,"enabled")||!new[]{"chrome","firefox","edge","safari","ios","android","random"}.Contains(S(u,"fingerprint")))throw new OperationException("TLS 指纹不在已支持范围。");outputTls["utls"]=u.DeepClone();
        }
        if(tuic)
        {
            var congestion=S(n,"congestion_control","cubic");var mode=S(n,"udp_relay_mode","native");
            if(congestion is not ("cubic" or "new_reno" or "bbr")||mode is not ("native" or "quic"))throw new OperationException("TUIC 拥塞控制或 UDP 中继模式无效。");
            if(B(n,"zero_rtt_handshake")||S(n,"heartbeat","10s")!="10s")throw new OperationException("TUIC 链接不能完整表达自定义心跳或 0-RTT，请导出完整客户端配置。");
            result["congestion_control"]=congestion;result["udp_relay_mode"]=mode;result["heartbeat"]="10s";result["zero_rtt_handshake"]=false;
        }
        return result;
    }
    public static JsonObject ToClash(JsonObject source,string name)
    {
        var n=Canonical(source,name);var p=n.Text("type");var c=new JsonObject{["type"]=p,["name"]=name,["server"]=n.Text("server"),["port"]=n.Number("server_port"),["udp"]=true,["skip-cert-verify"]=false};
        c[p=="vless"?"servername":"sni"]=n.Text("tls.server_name");if(p!="trojan")c["uuid"]=n.Text("uuid");if(p!="vless")c["password"]=n.Text("password");
        if(n.At("tls.alpn")!=null)c["alpn"]=n.At("tls.alpn")!.DeepClone();if(n.At("tls.utls")!=null)c["client-fingerprint"]=n.Text("tls.utls.fingerprint");
        if(p=="tuic"){c["congestion-controller"]=n.Text("congestion_control");c["udp-relay-mode"]=n.Text("udp_relay_mode");c["heartbeat-interval"]=10000;c["reduce-rtt"]=false;c["fast-open"]=false;}
        else{c["network"]="tcp";if(p=="vless"){c["tls"]=true;c["packet-encoding"]="xudp";}}
        return c;
    }
    public static JsonObject FromClash(JsonObject c,string name)
    {
        var p=S(c,"type");var tuic=p=="tuic";
        Fields(c,new[]{"type","name","server","port","udp","skip-cert-verify","alpn",p=="vless"?"servername":"sni",p=="trojan"?"password":"uuid"}.Concat(tuic?["password","congestion-controller","udp-relay-mode","heartbeat-interval","reduce-rtt","fast-open"]:p=="vless"?["tls","network","flow","client-fingerprint","packet-encoding"]:["tls","network","client-fingerprint"]).ToArray());
        if(S(c,"name")!=name||!B(c,"udp",true)||!tuic&&(S(c,"network") is not ("" or "tcp" or "raw")||p=="vless"&&!B(c,"tls")||c.ContainsKey("tls")&&!B(c,"tls")))throw new OperationException("TLS、UDP 或传输限制无法等效分享。");
        var n=new JsonObject{["type"]=p,["tag"]=name,["server"]=S(c,"server"),["server_port"]=I(c,"port"),["tls"]=new JsonObject{["enabled"]=true,["server_name"]=S(c,p=="vless"?"servername":"sni",S(c,"server")),["insecure"]=B(c,"skip-cert-verify")}};
        if(p!="trojan")n["uuid"]=S(c,"uuid");if(p!="vless")n["password"]=Password(c);if(p=="vless"){n["flow"]=S(c,"flow");if(c.ContainsKey("packet-encoding"))n["packet_encoding"]=S(c,"packet-encoding");}
        if(c["alpn"]!=null)n["tls"]!["alpn"]=c["alpn"]!.DeepClone();if(c.ContainsKey("client-fingerprint"))n["tls"]!["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=S(c,"client-fingerprint")};
        if(tuic)
        {
            if(I(c,"heartbeat-interval",10000)!=10000||B(c,"reduce-rtt")||B(c,"fast-open"))throw new OperationException("TUIC 自定义心跳、0-RTT 或 fast-open 不能通过通用链接保留。");
            n["congestion_control"]=S(c,"congestion-controller","cubic");n["udp_relay_mode"]=S(c,"udp-relay-mode","native");
        }
        return Canonical(n,name);
    }
    public static string Link(JsonObject source,string name)
    {
        var n=Canonical(source,name);static string E(string s)=>Uri.EscapeDataString(s);var p=n.Text("type");var host=n.Text("server");var auth=p=="vless"?n.Text("uuid"):p=="tuic"?n.Text("uuid")+":"+n.Text("password"):n.Text("password");
        var link=p+"://"+(p=="tuic"?E(n.Text("uuid"))+":"+E(n.Text("password")):E(auth))+"@"+(host.Contains(':')?"["+host+"]":host)+":"+n.Number("server_port")+"?sni="+E(n.Text("tls.server_name"));
        if(p=="tuic")link+="&congestion_control="+n.Text("congestion_control")+"&udp_relay_mode="+n.Text("udp_relay_mode")+"&allow_insecure=0";
        else{link+="&security=tls&type=tcp";if(p=="vless")link+="&encryption=none";if(n.At("tls.utls")!=null)link+="&fp="+E(n.Text("tls.utls.fingerprint"));}
        if(n.At("tls.alpn") is JsonArray alpn)link+="&alpn="+E(string.Join(',',alpn.Select(a=>a!.ToString())));return link+"#"+E(name);
    }
}
