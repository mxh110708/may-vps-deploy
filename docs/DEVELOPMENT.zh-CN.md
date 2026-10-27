# 开发与验证

日常使用请下载发行包；本页面向修改源码的维护者。先读[仓库约定](../AGENTS.md)、[安全说明](SECURITY.md)和[架构](DOTNET-ARCHITECTURE.zh-CN.md)。文档以 v0.9.38 的目录和脚本为基准。

## 结构

| 目录 | 责任 |
| --- | --- |
| `desktop/May.VpsDeploy.Desktop` | 当前 WinUI 3 桌面。 |
| `desktop/May.VpsDeploy.Core` | 跨平台业务模型和操作边界，不引用 Windows UI。 |
| `desktop/` 下适配与基础设施项目 | SSH.NET、Windows 凭据、文件权限与更新。 |
| `assets/remote/` | 受管远端 Bash 操作。 |
| `templates/client/`、`config/` | 公共模板、策略及固定资产。 |
| `scripts/`、`tests/` | 专用转换、打包和验证。 |
| `Start-VPSDeploy.ps1`、`src/`、`modules/` | 保留的 PowerShell CLI 与历史实现，不能当作桌面驱动。 |

## 准备和检查

当前桌面构建使用 .NET SDK 10.0.400；辅助脚本使用 PowerShell 7.4+、Python 3.9+。具体打包依赖以初始化和打包脚本为准；不要改变全局 PATH 以满足单个仓库。

在仓库根目录按所改行为选择检查：

```powershell
python -m pip install -r .\requirements-client-merge.txt
dotnet restore .\desktop\May.VpsDeploy.Tests\May.VpsDeploy.Tests.csproj --locked-mode
dotnet run --project .\desktop\May.VpsDeploy.Tests -c Release --no-restore -- $PWD
pwsh -NoProfile -File .\scripts\Test-NoSecrets.ps1 -ProjectRoot $PWD
```

PowerShell 主入口的完整离线回归：

```powershell
pwsh -NoProfile -File .\Start-VPSDeploy.ps1 -Mode ValidateProject
```

它已经包含主回归入口，不必再次运行同一批 `Run-Tests.ps1`。客户端生成变化还需固定核心兼容测试；更新或安装器变化需隔离真实生命周期测试。仅改文档时检查链接、示例、术语、源码合同和秘密即可，不需要借机安装应用或重跑生产部署。

## 本地包

```powershell
pwsh -NoProfile -File .\scripts\New-VpsReleasePackage.ps1 -Destination '<本地输出目录>' -Development
```

开发包不冒充正式更新。正式打包要求干净的 main、稳定版本元数据和完整对应内核源码材料，细节以脚本参数为准。构建、推送、发行和安装是不同授权范围；版本号不因纯文档修改而自动增加。

## 验证层级

解析／静态检查证明格式；模拟测试证明分支和事务判断；临时 Debian 的真实 systemd 测试证明相应生命周期；真实协议验收证明指定路径；生产观察与长测还需时间、报告新鲜度、同阶段资源和清理证据。报告必须写清缺口，不能用前一层替代后一层。

所有公开文档和夹具使用占位符。不要提交私人目录、实际实例信息、签名材料或完整运行配置。上游模块名、协议字段、历史文件名和许可证按其技术含义保留，不能为了品牌统一进行盲目替换。
