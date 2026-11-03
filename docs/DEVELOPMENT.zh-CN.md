# 开发与验证

日常使用请下载发行包；本页面向修改源码的维护者。先读[仓库约定](../AGENTS.md)、[安全说明](SECURITY.md)和[架构](DOTNET-ARCHITECTURE.zh-CN.md)。发行基线为 v0.9.41，各轮记录保留实施当时的验证边界。

## 资源总览专项

第三十一轮资源专项可用 `--resources-only` 单独运行，也已纳入 `--group operations`。公开证书读取行为使用 `tests/test_resource_certificates.py`，需要 OpenSSL 3；远端生产目标仍为 Debian，macOS CI 保留核心模型回归，不把系统 LibreSSL 当作 Debian OpenSSL 的等价验收。隐藏原生资源界面使用 `suite.resources`，维护界面可用 `suite.maintenance`，详见[资源指南](OPERATIONS-RESOURCES-ROUND-31-2026-11-03.zh-CN.md)。

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

完整 .NET 回归可拆成八个独立组运行，以便每组设置超时并定位问题。`--group` 选择完整入口中的对应功能，不替换断言；不带该参数时仍执行全部组。八组均通过才算完整分组回归通过：

```powershell
$groups = 'foundation', 'clients', 'xhttp', 'chains', 'quic', 'udp', 'server-stream', 'operations'
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

第三十轮 `--chain30-only` 已纳入 `--group chains`；`tests/test_chain30.py` 同时进入主校验和跨平台CI。真实内核／systemd矩阵分别使用 `--chain30-vm <全新IPv4三机清单> IPv4` 与 `--chain30-vm <另一套全新IPv6三机清单> IPv6`，夹具参数为 `--round21 --chain-underlay`；每组独立预算和身份，不能复用已完成业务矩阵的清单重新初始化。后台原生套件继续复用 `suite.tcp-forward`、`suite.tcp-chain`、`suite.wireguard`，详见[第三十轮](FORWARDING-WIREGUARD-ROUND-30-2026-11-02.zh-CN.md)。

共享实例追加功能的 `--shared-chains-only` 已纳入 `--group chains`，覆盖共享前置／中转、角色交叉、共享落地、TCP／UDP 共存、逐线路来源、待恢复和补偿。实际双线路用 `--shared-chains-vm <全新三机清单> IPv4` 与 `IPv6`；夹具 `tests/tcp-chain-vm-fixture.py --round21 --shared-chains` 仅开放两个固定测试入口，IPv6 矩阵另加 `--chain-underlay` 验证共享 WireGuard。各组显式预算、后台执行并清理；WinUI 仍用 `suite.tcp-chain`，详见[追加功能](SHARED-CHAINS-ROUND-25-2026-11-01.zh-CN.md)。原未发行入口曾误称 `chain25`，现按功能命名，历史日志不改写。

`--wireguard-only` 验证两端锁、归属、确认丢失、实际证据和恢复续做，已纳入 `--group chains`。`tests/test_wireguard.py` 的 Linux 文件边界检查在 Windows／macOS 明确跳过，由 Linux CI 补齐。完整内核与重启证据使用显式临时清单 `--wireguard-vm <manifest>`；夹具 `tests/tcp-chain-vm-fixture.py --wireguard` 只启动两台一次性 Debian，必须核对 DMI／标记并最终停止。可选 `--guest-apt-proxy` 只接受无认证 QEMU 主机网关代理，不能修改宿主或生产网络设置。

原生表单用已有后台接口 `suite.wireguard`，要求零窗口激活、零前台采样。测试不允许在生产归档中生成密钥、安装组件或重启机器。详见[第二十二轮](WIREGUARD-ROUND-22-2026-10-30.zh-CN.md)。

节点组原生后台回归：`suite.client-groups`（仅合成归档）；跨平台 .NET `clients` 组包含来源版本、双方案、冲突、实际配置生成／核心校验与导出拒绝测试。`tests/test_client_sources.py` 检查 Hysteria2／TUIC 的两种原生来源及联合读取。

第二十四轮的 `--chain24-only` 已纳入 `--group chains`，覆盖两段 WireGuard 引用、旧线路回归、业务证据和补偿。实际矩阵分别用 `--chain24-vm <全新三机清单> FrontRelay` 与 `RelayLanding`，每段使用另一套全新夹具；`tests/tcp-chain-vm-fixture.py --round21 --chain-underlay` 安装测试所需的 WireGuard 工具并限制启动预算。界面复用 `suite.tcp-chain`，禁止可见窗口。此入口不授权生产操作，详见[第二十四轮](CHAIN-WIREGUARD-ROUND-24-2026-11-01.zh-CN.md)。

## 来源同步与服务器分类专项

第二十九轮使用 `--server-stream-only`，模型／事务子集为 `--server-stream-model-only`，私有大文档传输专项为 `--server-probe-input-only`。完整专项单列 `--group server-stream`，避免把真实协议矩阵塞进已有UDP组导致超时；无参数完整入口仍包含它。使用固定 `MAY_TEST_XRAY` 与 `MAY_TEST_PYTHON` 才能执行本轮完整本机矩阵；缺少依赖的跳过按日志保留。Python `tests/test_server_stream_next_hops.py` 随主检查与跨平台CI执行。原生界面用 `suite.server-stream`，继续验证旧服务器出站与独立入站来源，详见[第二十九轮](SERVER-STREAM-NEXT-HOPS-ROUND-29-2026-11-02.zh-CN.md)。

第二十八轮使用 `--inbound-policy-only`，模型子集为 `--inbound-policy-model-only`，实际远端探测脚本子集为 `--inbound-policy-probe-only`；均已纳入 `--group chains`，完整路径需要固定 `MAY_TEST_XRAY` 与 `MAY_TEST_PYTHON`。Python `tests/test_inbound_policy.py` 随主检查及跨平台 CI 执行；真实核心矩阵另校验 .NET 生成负载与 Python 远端解析一致。WinUI 复用 `suite.inbounds`，别名 `suite.inbound-policy`，只操作合成归档并要求零激活／零前台采样。执行预算、证据范围及已知域名元数据差异见[第二十八轮](INBOUND-POLICY-ROUND-28-2026-11-02.zh-CN.md)。

原定第二十五、二十六轮分别使用 `--source-sync-only` 和 `--server-rule-sets-only`，并纳入 `--group clients`。前者覆盖调度、真实回环下载／代理、多个方案与节点组的批量事务及恢复；后者包含模型及固定核心的 AnyTLS／Reality 分类、附加落地、新旧版本实际路径。模型子集 `--server-rule-sets-model-only` 不等于实际连接验收。使用固定 `MAY_TEST_XRAY`，测试会核对其摘要；缺少核心不能记为通过。

第二十七轮使用 `--client-roundtrip-only`；其模型子集为 `--client-roundtrip-model-only`，完整模型及双核心真实协议矩阵已纳入 clients 组。原生后台接口新增 `suite.client-roundtrip` 并回归 `suite.client-share`；只用合成数据、隔离复制接收器和原生控件接口，不弹窗或修改系统剪贴板。详见[第二十七轮](CLIENT-OUTPUT-ROUND-27-2026-11-02.zh-CN.md)。

WinUI 使用既有隐藏接口 `suite.source-sync`、`suite.server-rule-sets`，继续回归 `suite.server-outbound`。合成归档中的定时器禁止联网，下载另由受控本机服务器验证；全部要求零窗口激活与零前台采样。调度身份索引不含 URL，实际缓存和事务使用加密私人归档，不可作为公开测试附件。用例、使用与边界见[第二十五轮](SOURCE-SYNC-ROUND-25-2026-11-01.zh-CN.md)、[第二十六轮](SERVER-RULESETS-ROUND-26-2026-11-01.zh-CN.md)。
