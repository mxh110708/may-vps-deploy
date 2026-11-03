using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

// Portable, bounded snapshots of supported primitives. They are expanded into
// native TCP rules; servers never download mutable rules or execute processors.
public static class ServerRuleSets
{
    public const int MaximumItems=2048;
    public const int MaximumExpandedRules=4096;
    public static string Id(string value)=>Regex.IsMatch(value,"^[a-z0-9][a-z0-9-]{0,63}$")?value:throw new OperationException("规则集 ID 须为 1–64 个小写字母、数字或连字符。");
    public static JsonObject Normalize(JsonNode? value)
    {
        if(value is not JsonObject set||set.Count!=5||set.Any(p=>p.Key is not ("Schema" or "Id" or "Name" or "Revision" or "Rules"))||set["Schema"] is not JsonValue version||!version.TryGetValue<int>(out var schema)||schema!=1)throw new OperationException("规则集格式不受支持；只接受有版本的域名／CIDR 清单。");
        foreach(var key in new[]{"Id","Name","Revision"})if(set[key] is not JsonValue text||!text.TryGetValue<string>(out _))throw new OperationException("规则集文本字段无效。");
        _=Id(set.Text("Id"));if(set.Text("Name").Length is <1 or >100||set.Text("Name").Any(char.IsControl)||!Regex.IsMatch(set.Text("Revision"),"^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})(?:-[a-zA-Z0-9.-]{1,24})?$"))throw new OperationException("规则集名称或版本无效，版本采用三段数字。");
        if(set["Rules"] is not JsonArray rules||rules.Count is <1 or >MaximumItems)throw new OperationException("规则集须有 1–2048 个明确匹配项。");
        var output=new JsonArray();var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var term in rules)
        {
            if(term is not JsonObject item||item.Count!=2||item.Any(p=>p.Key is not ("Kind" or "Value"))||item.Text("Kind") is not ("Domain" or "Suffix" or "Cidr"))throw new OperationException("规则集不接受动作、嵌套、正则、脚本或原生配置字段。");
            var input=item.DeepClone().AsObject();input["Action"]="NextHop";var normal=ServerDestinationRules.Normalize(new JsonArray(input))[0]!.AsObject();normal.Remove("Action");
            if(!seen.Add(normal.Text("Kind")+":"+normal.Text("Value")))throw new OperationException("规则集有重复的规范匹配项。");output.Add(normal.DeepClone());
        }
        return new(){["Schema"]=1,["Id"]=set.Text("Id"),["Name"]=set.Text("Name"),["Revision"]=set.Text("Revision"),["Rules"]=output};
    }
    public static string Digest(JsonObject set)=>ArchiveStore.Fingerprint(Normalize(set));
    public static JsonObject Rule(JsonObject set,string action="NextHop",string target="",Func<string,string>? targetIdentity=null)
    {
        var snapshot=Normalize(set);var rule=new JsonObject{["Kind"]="RuleSet",["Value"]=snapshot.Text("Id"),["Action"]=action,["RuleSet"]=snapshot};if(target!="")rule["Target"]=target;
        return ServerDestinationRules.Normalize(new JsonArray(rule),targetIdentity)[0]!.DeepClone().AsObject();
    }
    public static IEnumerable<JsonObject> Expand(JsonArray rules)
    {
        var count=0;
        foreach(var rule in rules.OfType<JsonObject>())
        {
            var terms=rule.Text("Kind")=="RuleSet"?Normalize(rule["RuleSet"])["Rules"]!.AsArray().OfType<JsonObject>():new[]{rule};
            foreach(var term in terms)
            {
                if(++count>MaximumExpandedRules)throw new OperationException("分类展开超过 4096 个匹配项，请缩小规则集。");
                var item=term.DeepClone().AsObject();item["Action"]=rule.Text("Action");if(rule.Text("Target")!="")item["Target"]=rule.Text("Target");yield return item;
            }
        }
    }
    public static IReadOnlyList<JsonObject> Builtins(AppPaths paths)
    {
        var academic=ArchiveStore.ReadJson(paths.Resolve("config/academic-services.policy.json"));var google=ArchiveStore.ReadJson(paths.Resolve("config/google-services.policy.json"));
        var scholar=academic.Strings("scholar_google_bases").Select(d=>"scholar."+d).ToArray();var research=academic.Strings("research_suffixes").Concat(scholar).ToHashSet(StringComparer.Ordinal);
        JsonObject Set(string id,string name,IEnumerable<(string Kind,string Value)> terms)=>Normalize(new JsonObject{["Schema"]=1,["Id"]=id,["Name"]=name,["Revision"]="1.0.0",["Rules"]=new JsonArray(terms.Distinct().Select(t=>(JsonNode?)new JsonObject{["Kind"]=t.Kind,["Value"]=t.Value}).ToArray())});
        var aiDomains=google["google_ai"]!.Strings("domain").Where(d=>!research.Any(s=>d==s||d.EndsWith("."+s,StringComparison.Ordinal))).Select(d=>("Domain",d));
        var aiSuffixes=google["google_ai"]!.Strings("domain_suffix").Where(d=>!research.Any(s=>d==s||d.EndsWith("."+s,StringComparison.Ordinal))).Select(d=>("Suffix",d));
        return [Set("campus-academic-cn","校园与境内学术",academic.Strings("campus_direct_suffixes").Select(d=>("Suffix",d))),
            Set("academic-research","学术研究与数据集",academic.Strings("research_suffixes").Select(d=>("Suffix",d)).Concat(scholar.Select(d=>("Suffix",d)))),
            Set("developer-tools","开发工具与框架",academic.Strings("developer_suffixes").Select(d=>("Suffix",d))),Set("google-ai-services","Google AI 服务（排除学术项）",aiDomains.Concat(aiSuffixes))];
    }
}
