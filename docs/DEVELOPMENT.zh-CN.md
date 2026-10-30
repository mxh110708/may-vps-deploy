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

完整 .NET 回归也可拆成七个独立组运行，以便每组设置超时并定位问题。`--group` 只选择原完整入口中的连续用例，不替换断言；不带该参数时仍按原顺序执行全部组。七组均通过才算完整分组回归通过：

```powershell
$groups = 'foundation', 'clients', 'xhttp', 'chains', 'quic', 'udp', 'operations'
foreach ($group in $groups) {
    dotnet .\desktop\May.VpsDeploy.Tests\bin\Release\net10.0\May.VpsDeploy.Tests.dll $PWD --group $group
    if ($LASTEXITCODE -ne 0) { throw "Regression group failed: $group" }
}
```

先构建测试项目。需要真实本机协议用例时设置 `MAY_TEST_PYTHON` 与固定 Xray 的 `MAY_TEST_XRAY`；SSH/SFTP 专项使用 `MAY_TEST_SSH_PYTHON`。后台运行器须给各组独立超时并关闭自己的子进程，不能将超时、缺失本机依赖或仅模型通过记为真实协议通过。原生 WinUI 使用已有后台测试接口，禁止弹出测试窗口。

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

## WireGuard 专项回归

`--wireguard-only` 验证两端锁、归属、确认丢失、实际证据和恢复续做，已纳入 `--group chains`。`tests/test_wireguard.py` 的 Linux 文件边界检查在 Windows／macOS 明确跳过，由 Linux CI 补齐。完整内核与重启证据使用显式临时清单 `--wireguard-vm <manifest>`；夹具 `tests/tcp-chain-vm-fixture.py --wireguard` 只启动两台一次性 Debian，必须核对 DMI／标记并最终停止。可选 `--guest-apt-proxy` 只接受无认证 QEMU 主机网关代理，不能修改宿主或生产网络设置。

原生表单用已有后台接口 `suite.wireguard`，要求零窗口激活、零前台采样。测试不允许在生产归档中生成密钥、安装组件或重启机器。详见[第二十二轮](WIREGUARD-ROUND-22-2026-10-30.zh-CN.md)。

节点组原生后台回归：`suite.client-groups`（仅合成归档）；跨平台 .NET `clients` 组包含来源版本、双方案、冲突、实际配置生成／核心校验与导出拒绝测试。`tests/test_client_sources.py` 检查 Hysteria2／TUIC 的两种原生来源及联合读取。
