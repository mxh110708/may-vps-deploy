using System.Text.Json;

namespace Mxh.VpsDeploy.Core;

public static class SafeFailures
{
    // Unknown exception text and remote output can contain credentials.
    public static OperationException Describe(Exception error, bool needsRecovery = false)
    {
        if (error is OperationException safe)
            return new(safe.Message, needsRecovery || safe.NeedsRecovery, safe.Code ?? "OperationRejected", safe.NextAction);
        return error switch
        {
            UnauthorizedAccessException => new("无法访问本地文件，当前账号没有所需权限。", needsRecovery, "LocalAccessDenied", "核对应用目录和管理密钥的访问权限；不要修改原始私钥权限。"),
            FileNotFoundException or DirectoryNotFoundException => new("所需的本地文件或目录不存在。", needsRecovery, "LocalFileMissing", "核对应用文件与所选私人文件的位置。"),
            JsonException or FormatException => new("步骤返回的数据或本地记录格式不符合预期。", needsRecovery, "InvalidStepData", "查看失败阶段；保留归档，核对数据格式后再继续。"),
            TimeoutException => new("当前步骤超时，尚未获得完整结果。", needsRecovery, "StepTimeout", "核对网络与任务阶段；有未确认写入时先核对事务。"),
            IOException => new("读取或写入本地文件失败。", needsRecovery, "LocalIoFailure", "核对磁盘空间、文件占用和应用目录。"),
            _ => new("当前步骤遇到未分类错误。错误类型：" + error.GetType().Name + "。", needsRecovery, "UnexpectedFailure", "查看记录中的实例、失败阶段和错误代码；保留归档以便排查。")
        };
    }
    public static OperationException Remote(CommandResult result, string description)
    {
        try
        {
            var phase = RemoteAssets.Marker(result.Output, "PROXY_UPGRADE_FAILURE", false);
            var detail = phase switch { "download" => "代理核心发行包下载失败。", "checksum" => "代理核心发行包 SHA256 不匹配，未替换程序。", "archive" => "代理核心发行包内容不受支持，未替换程序。", "version" => "代理核心程序版本与目标不一致，未替换程序。", "configuration" => "新核心未通过现有配置检查，未替换程序。", "install" => "代理核心程序替换或写入后校验失败。", _ => "" };
            if (detail != "") return new(detail, code: "ProxyCoreUpgradeFailed", nextAction: "核对任务中的目标版本和失败阶段；本轮按协议范围恢复后可重新审阅。");
        }
        catch (FormatException) { }
        try
        {
            var code = RemoteAssets.Marker(result.Output, "COMPONENT_RELEASE_FAILURE", false);
            var detail = code switch
            {
                "ComponentReleaseNotStable" => "官方查询返回测试版或草稿，未作为稳定升级目标。",
                "ComponentReleaseAssetMissing" => "官方发行缺少唯一的 amd64 资产，未生成升级候选。",
                "ComponentReleaseDigestMissing" => "官方资产缺少可验证的 SHA256 或资产身份不匹配，已停止查询。",
                "ComponentReleaseRateLimited" => "官方版本接口限制了请求，稍后可重新查询。",
                "ComponentReleaseHttpFailed" => "官方版本接口返回 HTTP 错误，未取得升级目标。",
                "ComponentReleaseNetworkFailed" => "VPS 无法完成官方版本查询，请核对网络与 DNS。",
                "ComponentReleaseUnsupported" => "官方发行格式或版本不受支持，未生成升级候选。",
                _ => ""
            };
            if (detail != "") return new(detail, code: code, nextAction: "重新查询官方版本或选择应用固定版本；不会自动升级。 ");
        }
        catch (FormatException) { }
        try
        {
            var code = RemoteAssets.Marker(result.Output, "KERNEL_FAILURE_CODE", false);
            var detail = code switch
            {
                "KernelVerifierMissing" => "远端缺少可用的内核签名验证工具，需要 gpgv 或支持明文签名的 sqv。",
                "KernelSignatureRejected" => "官方内核元数据的签名未通过验证，已停止操作。",
                "KernelSigningKeyMismatch" => "内核元数据签名与应用固定的官方公钥指纹不一致，已停止操作。",
                "KernelIndexHashMismatch" => "内核包索引与已验证签名中的摘要不一致，已停止操作。",
                "KernelRepositoryForbidden" => "官方内核仓库拒绝了请求（HTTP 403）。",
                "KernelRepositoryRateLimited" => "官方内核仓库限制了请求频率（HTTP 429）。",
                "KernelRepositoryHttpFailed" => "官方内核仓库返回 HTTP 错误，未取得有效元数据。",
                "KernelRepositoryDnsFailed" => "VPS 无法解析官方内核仓库域名。",
                "KernelRepositoryTimeout" => "VPS 查询官方内核仓库超时。",
                "KernelRepositoryUnavailable" => "VPS 无法连接官方内核仓库。",
                "KernelMetadataRejected" => "官方内核元数据不符合受信任的兼容 LTS 要求，已停止操作。",
                "KernelOperationRefused" => "内核步骤未通过安全检查；请核对内核兼容性与事务状态。",
                _ => ""
            };
            if (detail != "") return new(detail, code: code, nextAction: code.StartsWith("KernelRepository", StringComparison.Ordinal) ? "核对 VPS 的 DNS 和仓库连接后重新检查版本；安装时仍需重新审阅。" : "查看内核与网络配置中的检查结果；保留归档，核对所列依赖、签名或事务状态。");
        }
        catch (FormatException) { }
        try
        {
            var phase = RemoteAssets.Marker(result.Output, "MONITORING_FAILURE_PHASE", false);
            var detail = phase switch
            {
                "download" => "监控组件下载或摘要校验失败。",
                "binary-check" => "监控组件程序版本或安装路径检查失败。",
                "service-start" => "监控服务启动失败。",
                "service-process" => "监控服务的运行进程尚未通过核对。",
                "controller-guide" => "主控首次初始化接口尚未就绪。",
                "controller-initialization" => "主控管理员初始化失败。",
                "controller-login" => "主控管理员登录验收失败。",
                "tunnel-readiness" => "Tunnel 连接器未能在限定时间内连接 Cloudflare。",
                "readiness" => "监控组件接口就绪检查失败。",
                _ => ""
            };
            if (detail != "") return new(detail, code: "MonitoringStepFailed", nextAction: "核对本步骤的服务日志、网络与组件配置；本轮新增内容按事务范围恢复。");
        }
        catch (FormatException) { }
        var installation = RemoteAssets.Marker(result.Output, "INSTALLATION_CHECK", false);
        if (installation != "")
        {
            try
            {
                var check = System.Text.Json.Nodes.JsonNode.Parse(installation);
                if (!check.Flag("Allowed") && check.Text("Code") is "ComponentExists" or "PortBusy") return new(check.Text("Code") == "ComponentExists" ? "远端已有该组件或残留文件，未覆盖安装。请先核对并纳管。" : "新组件端口被占用，未覆盖其他服务。请选择独立端口。", code: check.Text("Code"));
            }
            catch (JsonException) { }
        }
        var reason = result.ExitCode == 127 || result.Error.Contains("command not found", StringComparison.OrdinalIgnoreCase) ? "远端缺少所需命令。" :
            result.Error.Contains("Permission denied", StringComparison.OrdinalIgnoreCase) ? "远端执行权限不足。" :
            result.Error.Contains("No space left on device", StringComparison.OrdinalIgnoreCase) ? "远端磁盘空间不足。" :
            result.Error.Contains("Could not resolve", StringComparison.OrdinalIgnoreCase) || result.Error.Contains("Temporary failure in name resolution", StringComparison.OrdinalIgnoreCase) ? "远端域名解析失败。" :
            result.Error.Contains("Connection timed out", StringComparison.OrdinalIgnoreCase) ? "远端网络请求超时。" :
            result.Error.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase) ? "远端所需文件不存在。" : "远端步骤返回非零退出码。";
        return new(description + "（退出码 " + result.ExitCode + "）。" + reason, code: "RemoteStepFailed", nextAction: "核对本步骤的环境与依赖；存在未确认事务时先核对恢复状态。");
    }
}
