using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace Mxh.VpsDeploy.Core;

public static class BbrKernels
{
    public const string Owner = "mxh-google-bbr-v3";
    public const string Repository = "https://github.com/google/bbr";
    public const string Vendor = "Google BBR v3 source / MXH local build";
    public const string SourceNotice = "来源为 Google 官方 BBR v3 源码，固定版由 MXH 预编译并随应用提供；产物不是 Google 或 Debian 发布的二进制内核。v3 分支不等于 LTS 安全维护分支。";
    public static readonly string[] SourceNames = ["commit.json", "Makefile", "tcp_bbr.c"];
    public static bool Pending(JsonObject state) => state["KernelUpgrade"] != null && state.Text("KernelUpgrade.Phase") is not ("Committed" or "RolledBack" or "Aborted");
    public static bool Official(JsonObject catalog) => catalog.Number("SchemaVersion") == 2 && catalog.Text("Repository") == Repository && catalog.Text("Branch") == "v3" && catalog.Text("Vendor") == Vendor && catalog.Number("BuildRecipe") == 1;
    public static bool AcceptedRuntime(JsonObject state, JsonObject runtime) => state["KernelUpgrade"] is JsonObject record && record.Number("SchemaVersion") == 2 && record.Text("Owner") == Owner && record.Text("Delivery") == "Prebuilt" && record.Text("Phase") == "Committed" && record["Catalog"] is JsonObject catalog && Official(catalog) && Regex.IsMatch(catalog.Text("Prebuilt.Sha256"), "^[a-f0-9]{64}$") && runtime.Text("Kernel") == catalog.Text("Kernel") && runtime.Text("BbrVersion") == "v3" && Regex.IsMatch(record.Text("NewImageSha256"), "^[a-f0-9]{64}$") && Regex.IsMatch(record.Text("NewInitrdSha256"), "^[a-f0-9]{64}$");
    public const string PackageLabel = "Google BBR v3 · MXH 固定预编译包";
    public static void Validate(JsonObject options)
    {
        if (options.Text("Action") is not ("Check" or "Install" or "Activate" or "Reconcile" or "Rollback" or "RollbackOriginal") || options.Any(p => p.Key is not ("Action" or "CatalogId" or "CatalogSha256" or "SourceCommit"))) throw new OperationException("请选择明确的 BBR 内核操作。");
        if (options.Text("Action") == "Install" && options.Text("CatalogId") == "" || options.Text("Action") != "Install" && options.ContainsKey("CatalogId")) throw new OperationException("安装需指定随应用提供的固定内核，其他操作沿用原事务。");
        if (options.Text("Action") == "Install" ? !Regex.IsMatch(options.Text("CatalogSha256"), "^[a-f0-9]{64}$") || !Regex.IsMatch(options.Text("SourceCommit"), "^[a-f0-9]{40}$") : options.ContainsKey("CatalogSha256") || options.ContainsKey("SourceCommit")) throw new OperationException("安装必须锁定已审阅的完整提交和源码材料指纹。");
    }
    public static JsonObject Catalog(AppPaths paths)
    {
        var catalog = ArchiveStore.ReadJson(paths.Resolve("config/kernel-catalog.json"));
        var materials = SourceNames.ToDictionary(n => n, n => File.ReadAllBytes(paths.Resolve("assets/kernel/" + n)));
        ValidateMaterials(catalog, materials); ValidatePrebuilt(paths, catalog, false); return catalog;
    }
    public static string FileDigest(string path)
    {
        SafePath.CheckLinks(path); using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
    public static JsonObject ValidatePrebuilt(AppPaths paths, JsonObject catalog, bool package = true)
    {
        if (catalog["Prebuilt"] is not JsonObject artifact) throw new OperationException("内置预编译包清单缺失。");
        var manifestPath = paths.Resolve("assets/kernel/build-manifest.json");
        if (FileDigest(manifestPath) != artifact.Text("ManifestSha256")) throw new OperationException("内核构建清单指纹不匹配。");
        var manifest = ArchiveStore.ReadJson(manifestPath);
        if (manifest.Number("SchemaVersion") != 1 || manifest.Text("BuildProfile") != "debian-generic-amd64-v1" || !manifest.Flag("GitFsckPassed")
            || new[] { "Kernel", "Package", "PackageVersion", "Architecture" }.Any(k => manifest.Text(k) != catalog.Text(k))
            || manifest.Text("SourceCommit") != catalog.Text("Commit") || manifest.Text("SourceTree") != catalog.Text("Tree") || manifest.Text("SourceMaterialsSha256") != catalog.Text("Sha256")
            || manifest.Text("PackageSha256") != artifact.Text("Sha256") || manifest.Number("PackageBytes") != artifact.Number("Bytes")
            || artifact.Text("File") != "kernel.deb" || !Regex.IsMatch(artifact.Text("Sha256"), "^[a-f0-9]{64}$")
            || artifact.Number("Bytes") is <= 0 or > 1073741824
            || FileDigest(paths.Resolve("assets/kernel/kernel.config")) != manifest.Text("ConfigSha256")
            || FileDigest(paths.Resolve("assets/kernel/input.config")) != manifest.Text("InputConfigSha256")) throw new OperationException("内核包、构建配置与官方源码身份不一致。");
        if (package)
        {
            var file = paths.Resolve("assets/kernel/kernel.deb"); SafePath.CheckLinks(file);
            if (new FileInfo(file).Length != artifact.Number("Bytes") || FileDigest(file) != artifact.Text("Sha256")) throw new OperationException("内置内核包大小或 SHA256 不匹配，未上传或安装。");
        }
        return manifest;
    }
    public static string InstallDescription(JsonObject? catalog)
    {
        if (catalog?["Prebuilt"] is not JsonObject prebuilt) throw new OperationException("缺少随应用提供的预编译内核清单。");
        return "\n安装方式：应用内置预编译包\n内核包 SHA256：" + prebuilt.Text("Sha256") + "\n内核包大小：" + prebuilt.Number("Bytes") + " 字节\n上传已验证的通用 amd64 内核包，VPS 再次核对大小、SHA256、包身份及安装计划，仅新增此内核，不安装编译依赖。需至少 2 GiB 根目录空间、512 MiB 启动空间；内存建议至少 512 MiB（系统识别总量需 384 MiB、当前可用需 256 MiB）。保留旧内核，重启另行审阅；上传不计入测速预算。";
    }
    private static void ValidateMaterials(JsonObject cat, IReadOnlyDictionary<string, byte[]> materials)
    {
        var sha = cat.Text("Commit"); var version = cat.Text("BaseKernel");
        if (!Official(cat) || cat.ContainsKey("Selection") || cat.Text("Architecture") != "amd64" || cat.Number("BbrVersion") != 3 || !Regex.IsMatch(sha, "^[a-f0-9]{40}$") || !Regex.IsMatch(cat.Text("Tree"), "^[a-f0-9]{40}$") || !Regex.IsMatch(version, @"^[0-9]+\.[0-9]+\.[0-9]+$") || cat["SourceFiles"] is not JsonObject files || files.Count != SourceNames.Length) throw new OperationException("仅支持随应用固定的 Google 官方 v3 源码与预编译包。");
        var kernel = version + "-mxh-bbr3-" + sha[..12];
        if (cat.Text("Id") != "google-bbr-v3-" + sha[..12] || cat.Text("Kernel") != kernel || cat.Text("Package") != "linux-image-" + kernel || cat.Text("PackageVersion") != version + "-1.mxh" + sha[..12]) throw new OperationException("源码提交与构建产物身份不一致。");
        foreach (var name in SourceNames)
            if (!materials.TryGetValue(name, out var bytes) || bytes.Length is 0 or > 1048576 || ArchiveStore.Digest(bytes) != files[name]?.ToString()) throw new OperationException("官方源码材料变化，请更新应用。");
        var digest = ArchiveStore.Digest(Encoding.UTF8.GetBytes(string.Join("\n", SourceNames.Order(StringComparer.Ordinal).Select(n => n + ":" + files[n]?.ToString()))));
        if (cat.Text("Sha256") != digest) throw new OperationException("源码材料指纹不匹配。");
        JsonObject commit;
        try { commit = JsonNode.Parse(materials["commit.json"])!.AsObject(); }
        catch (Exception error) when (error is System.Text.Json.JsonException or InvalidOperationException) { throw new OperationException("官方提交元数据无效。"); }
        if (commit.Text("sha") != sha || commit.Text("tree.sha") != cat.Text("Tree") || commit.Text("committer.date") != cat.Text("SourceDate") || !DateTimeOffset.TryParse(cat.Text("SourceDate"), out var date) || date > DateTimeOffset.UtcNow.AddMinutes(5)) throw new OperationException("官方提交身份或日期不一致。");
        var makefile = Encoding.UTF8.GetString(materials["Makefile"]);
        string Part(string key)
        {
            var matches = Regex.Matches(makefile, "^" + key + @"[ \t]*=[ \t]*([^\r\n]*)$", RegexOptions.Multiline);
            if (matches.Count != 1) throw new OperationException("官方内核版本文件无效。");
            return matches[0].Groups[1].Value.Trim();
        }
        if (Part("EXTRAVERSION") != "" || string.Join('.', new[] { "VERSION", "PATCHLEVEL", "SUBLEVEL" }.Select(Part)) != version || !Regex.IsMatch(Encoding.UTF8.GetString(materials["tcp_bbr.c"]), @"^#define\s+BBR_VERSION\s+3\s*$", RegexOptions.Multiline)) throw new OperationException("官方源码未确认是受支持的 BBR v3 稳定基础版本。");
    }
    public static string Label(string action) => action switch { "Check" => "检查官方来源与兼容性", "Install" => "安装 Google BBR v3 内核", "Activate" => "重启并验收 BBR v3", "Rollback" => "回退上一内核", "RollbackOriginal" => "回到 VPS 原有内核", _ => "核对并完成内核事务" };
    private static Version? BaseVersion(string value) => Regex.Match(value, @"^([0-9]+\.[0-9]+\.[0-9]+)(?:[-+]|$)") is { Success: true } m && Version.TryParse(m.Groups[1].Value, out var version) ? version : null;
    public static bool CanUpgrade(JsonObject? transaction, JsonObject? check, JsonObject catalog)
    {
        if (!Official(catalog) || check?.Flag("Compatible") != true || check.Text("Kernel") == catalog.Text("Kernel") || BaseVersion(check.Text("Kernel")) is not { } current || BaseVersion(catalog.Text("Kernel")) is not { } next || next < current) return false;
        if (check.Text("BbrVersion") != "v3") return transaction == null || transaction.Text("Phase") is "Aborted" or "RolledBack";
        var running = check.Text("Kernel");
        var owned = transaction?.Text("Phase") == "Committed" && transaction.Text("Catalog.Kernel") == running || transaction?.Text("Phase") is "Aborted" or "RolledBack" && transaction.Text("PreviousTransaction") != "" && transaction.Text("OldKernel") == running;
        return owned && transaction?["Catalog"] is JsonObject previous && Official(previous) && (next > current || previous.Text("Commit") != catalog.Text("Commit") && DateTimeOffset.TryParse(previous.Text("SourceDate"), out var prior) && DateTimeOffset.TryParse(catalog.Text("SourceDate"), out var later) && later > prior);
    }
    public static string PhaseLabel(string phase) => phase switch { "Preparing" => "正在准备，需核对", "Installing" => "正在安装，可稍后核对", "Prepared" => "已安装，等待审阅重启", "BootRequested" => "已请求重启，等待验收", "Booted" => "新内核已启动，等待提交", "Committed" => "BBR v3 已验收并设为默认", "RollbackRequested" => "正在回到旧内核", "RolledBack" => "已回退旧内核", "AutoRolledBack" => "保护机制已回到旧内核，需核对", "Aborted" => "已结束准备，旧内核继续运行", "InstallFailed" => "安装失败，需核对后结束准备", _ => "状态未确认，请核对" };
}
