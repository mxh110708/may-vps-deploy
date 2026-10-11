using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public static class BbrKernels
{
    public static bool Pending(JsonObject state) => state["KernelUpgrade"] != null && state.Text("KernelUpgrade.Phase") is not ("Committed" or "RolledBack" or "Aborted");
    public static void Validate(JsonObject options)
    {
        if (options.Text("Action") is not ("Check" or "Install" or "Activate" or "Reconcile" or "Rollback") || options.Any(p => p.Key is not ("Action" or "CatalogId" or "CatalogSha256" or "Source"))) throw new OperationException("请选择明确的 BBR 内核操作。");
        if (options.Text("Action") == "Install" && options.Text("CatalogId") == "" || options.Text("Action") != "Install" && options.ContainsKey("CatalogId")) throw new OperationException("内核安装需指定受管版本，其他操作沿用原事务。");
        if (options.ContainsKey("Source") && (options.Text("Action") is not ("Check" or "Install") || options.Text("Source") is not ("Fixed" or "Latest"))) throw new OperationException("请选择应用固定版本或官方最新兼容 LTS。");
        if (options.ContainsKey("CatalogSha256") && (options.Text("Action") != "Install" || !Regex.IsMatch(options.Text("CatalogSha256"), "^[a-f0-9]{64}$")) || options.Text("Action") == "Install" && options.Text("Source") == "Latest" && !options.ContainsKey("CatalogSha256")) throw new OperationException("最新内核安装必须锁定已审阅的包哈希。");
    }
    public static JsonObject Catalog(AppPaths paths)
    {
        var catalog = ArchiveStore.ReadJson(paths.Resolve("config/kernel-catalog.json"));
        if (catalog.Number("SchemaVersion") != 1 || catalog.Text("Architecture") != "amd64" || catalog.Number("BbrVersion") != 3 || catalog.Text("Repository") != "https://deb.xanmod.org/" || catalog.Text("Package") != "linux-image-" + catalog.Text("Kernel")) throw new OperationException("受管内核目录不受支持。");
        foreach (var name in new[] { "xanmod.gpg", "InRelease", "Packages.gz" })
        {
            using var stream = File.OpenRead(paths.Resolve("assets/kernel/" + name));
            if (Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant() != catalog["SourceFiles"]?[name]?.ToString()) throw new OperationException("内核签名材料发生变化，拒绝安装。");
        }
        return catalog;
    }
    public static JsonObject Candidate(AppPaths paths, string relative, string source)
    {
        var fixedCatalog = Catalog(paths);
        if (source == "Fixed") return new() { ["Catalog"] = fixedCatalog };
        if (source != "Latest") throw new OperationException("未知内核来源。");
        var file = SafePath.Resolve(paths.Instance(relative), "kernel-latest-candidate.json");
        if (!File.Exists(file) || new FileInfo(file).Length > 1048576) throw new OperationException("请先联网查询最新兼容 LTS。");
        var candidate = ArchiveStore.ReadJson(file); ValidateCandidate(candidate, fixedCatalog); return candidate;
    }
    public static void ValidateCandidate(JsonObject candidate, JsonObject anchor)
    {
        var cat = candidate["Catalog"] as JsonObject ?? throw new OperationException("缺少已核验内核版本。");
        if (cat.Text("Selection") != "Latest" || cat.Number("SchemaVersion") != 1 || cat.Text("Repository") != anchor.Text("Repository") || cat.Text("SigningFingerprint") != anchor.Text("SigningFingerprint") || cat.Text("Architecture") != "amd64" || cat.Number("BbrVersion") != 3 || cat.Text("Package") != "linux-image-" + cat.Text("Kernel") || !Regex.IsMatch(cat.Text("Kernel"), @"^[0-9]+\.[0-9]+\.[0-9]+-x64v1-xanmod[0-9]+$") || !Regex.IsMatch(cat.Text("Sha256"), "^[a-f0-9]{64}$")) throw new OperationException("最新内核来源、签名或包身份不匹配。");
        if (!DateTimeOffset.TryParse(candidate.Text("FetchedAt"), out var fetched) || fetched > DateTimeOffset.UtcNow.AddMinutes(5) || fetched < DateTimeOffset.UtcNow.AddHours(-24)) throw new OperationException("最新版本查询超过 24 小时，请重新查询后审阅。");
        foreach (var name in new[] { "xanmod.gpg", "InRelease", "Packages.gz" })
        {
            byte[] data;
            try { data = Convert.FromBase64String(candidate["Sources"]?[name]?.ToString() ?? ""); }
            catch (FormatException) { throw new OperationException("最新版本签名材料无效。"); }
            if (data.Length == 0 || data.Length > 2097152 || ArchiveStore.Digest(data) != cat["SourceFiles"]?[name]?.ToString()) throw new OperationException("最新版本签名材料变化，请重新查询。");
        }
        if (cat["SourceFiles"]?["xanmod.gpg"]?.ToString() != anchor["SourceFiles"]?["xanmod.gpg"]?.ToString()) throw new OperationException("签名信任锚变化，需要更新应用。");
    }
    public static string Label(string action) => action switch { "Check" => "检查兼容性", "Install" => "安装 BBR v3 内核", "Activate" => "重启并验收 BBR v3", "Rollback" => "回退旧内核", _ => "核对并完成内核事务" };
    public static string PhaseLabel(string phase) => phase switch { "Preparing" => "正在准备，需核对", "Installing" => "后台安装中", "Prepared" => "已安装，等待审阅重启", "BootRequested" => "已请求重启，等待验收", "Booted" => "新内核已启动，等待提交", "Committed" => "BBR v3 已验收并设为默认", "RollbackRequested" => "正在回到旧内核", "RolledBack" => "已回退旧内核", "AutoRolledBack" => "保护机制已回到旧内核，需核对", "Aborted" => "已结束安装准备，旧内核继续运行", "InstallFailed" => "安装失败，需核对后结束准备", _ => "状态未确认，请核对" };
}
