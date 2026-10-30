using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class InboundRendering
{
    private static JsonObject XrayXhttp(JsonObject inbound, JsonObject credentials, JsonObject outbound)
    {
        var options = inbound["Options"]!; var clients = new JsonArray(inbound.Strings("UserIds").Select(id => (JsonNode)new JsonObject { ["id"] = credentials.Text("Users." + id + ".Value"), ["email"] = id }).ToArray());
        var xhttp=new JsonObject { ["host"] = options.Text("Transport.Host"), ["path"] = options.Text("Transport.Path"), ["mode"] = options.Text("Transport.Mode","auto") };
        if(options.At("Transport.Extra") is JsonObject extra&&extra.Count>0)xhttp["extra"]=extra.DeepClone();
        var stream = new JsonObject { ["network"] = "xhttp", ["security"] = options.Text("Security") == "TLS" ? "tls" : "reality", ["xhttpSettings"] = xhttp };
        if (options.Text("Security") == "TLS")
        {
            var cert = credentials["Certificates"]![inbound.Text("CertificateId")]!;
            stream["tlsSettings"] = new JsonObject { ["serverName"] = options.Text("ServerName"), ["minVersion"] = "1.3", ["maxVersion"] = "1.3", ["alpn"] = new JsonArray(VlessXhttp.Alpn(options.Text("Transport.HTTPVersion","2"))), ["certificates"] = new JsonArray(new JsonObject { ["certificate"] = Lines(cert.Text("CertificatePem")), ["key"] = Lines(cert.Text("PrivateKeyPem")) }) };
        }
        else stream["realitySettings"] = new JsonObject { ["show"] = false, ["target"] = options.Text("Reality.HandshakeServer") + ":" + options.Number("Reality.HandshakePort"), ["xver"] = 0, ["serverNames"] = new JsonArray(options.Text("ServerName")), ["privateKey"] = credentials.Text("Inbounds." + inbound.Text("Id") + ".RealityPrivateKey"), ["shortIds"] = new JsonArray(options.Text("Reality.ShortId")) };
        var rules = new JsonArray(); if (outbound.Text("Family") != "Auto") rules.Add(new JsonObject { ["type"] = "field", ["ip"] = new JsonArray(outbound.Text("Family") == "IPv4" ? "::/0" : "0.0.0.0/0"), ["outboundTag"] = "block" });
        return new JsonObject
        {
            ["log"] = new JsonObject { ["access"] = "none", ["loglevel"] = "warning" },
            ["inbounds"] = new JsonArray(new JsonObject { ["tag"] = inbound.Text("Id"), ["listen"] = inbound.Text("Listener.Address"), ["port"] = inbound.Number("Listener.Port"), ["protocol"] = "vless", ["settings"] = new JsonObject { ["decryption"] = "none", ["clients"] = clients }, ["streamSettings"] = stream }),
            ["outbounds"] = new JsonArray(new JsonObject { ["tag"] = "egress", ["protocol"] = "freedom", ["settings"] = new JsonObject { ["domainStrategy"] = outbound.Text("Family") switch { "IPv4" => "ForceIPv4", "IPv6" => "ForceIPv6", _ => "AsIs" } } }, new JsonObject { ["tag"] = "block", ["protocol"] = "blackhole" }),
            ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = rules }
        };
    }
}
