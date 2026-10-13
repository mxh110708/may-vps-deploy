# MXH VPS Deploy 模块与内部结构

本文面向维护脚本的人。普通使用者应先阅读 [中文完整使用手册](USER-GUIDE.zh-CN.md)。

## 原生应用边界

正式桌面入口是 `desktop/Mxh.VpsDeploy.Desktop`。界面收集表单并展示审阅与进度，由 Core 的任务协调器锁定实例、来源和具体操作，再调用 `WorkflowEngine`。Infrastructure 提供 SSH.NET、客户端核心、文件生成和测量适配；Windows 适配器负责凭据保护、托盘、窗口及安装更新。Core 不依赖 WinUI、PowerShell 或 Windows API。

远端脚本和配置生成器由两个控制端共用。远端维护使用事务身份、期限与锁；首次部署使用单独基线，未知结果先核对状态。协议、网络、防火墙、监控、内核各有恢复范围；客户端导出是独立的本地双文件事务，不属于远端部署事务。桌面新部署支持多用途选择，追加安装支持组合组件，两个入口可在不同端口共存；受管状态以实际清单为准。

以下模块图、菜单编号、单角色向导及 OpenSSH 行为描述属于保留的传统 CLI。原生 EXE 不加载这些向导或历史 WPF 桥接；两类控制端的凭据与未完成事务不能未经转换直接重放。此次边界修复和验证见 [v0.9.21](TESTING-0.9.21.zh-CN.md)。

## 传统 CLI 结构总览

```text
Start-VPSDeploy.ps1
  └─ src/VpsDeploy.Core.psm1          主入口、向导、上下文、模块流水线
       ├─ src/VpsDeploy.Import.ps1     既有 VPS 纳管
       ├─ src/VpsDeploy.Migration.ps1  协议生命周期与独立网络调优
       ├─ src/VpsDeploy.Operations.ps1 运维中心
       └─ src/VpsDeploy.ClientConfig.ps1 客户端权威配置设计器

modules/*.ps1                         可排序的新部署/生命周期模块
assets/remote/*.sh                    通过 stdin 参数执行的远端脚本
templates/client/*                    无个人数据的客户端基础模板
config/*.json                         通用默认与固定版本目录
vendor/test-cores/windows-amd64/*     经校验后供 Windows 控制端验收的官方核心压缩包
tests/Run-Tests.ps1                   跨模块回归、交互和秘密扫描
```

主菜单导航属于核心而不是业务模块：主菜单 `9` 才退出，子层统一使用 `0` 返回。新增交互入口必须复用 `Read-VpsText`、`Read-VpsYesNo` 和 `Read-VpsMenu`，不能自行发明另一套返回方式。

正式运行拓扑是 Windows amd64 控制端通过 OpenSSH 管理 Debian 12/13 amd64 VPS。新建、Import 和维护上下文都必须调用同一 OS/架构门禁；Debian 容器 CI 不是 Linux 控制端支持承诺。

## 模块定义

`modules/*.ps1` 每个文件返回一个模块定义 Hashtable：

```powershell
@{
    Id          = 'example'
    Name        = '示例模块'
    Order       = 500
    Roles       = @('RealityEntry', 'MonitorOnly')
    Requires    = @('audit')
    IsEnabled   = { param($Context) $true }
    Invoke      = { param($Context) }
}
```

核心按 `Order` 排序，并验证 `Id` 唯一、依赖存在且位于之前。删除模块文件即可移除功能；新增模块不需要修改入口脚本。

当前角色：

- `RealityEntry`：Xray VLESS + REALITY + Vision；
- `AnyTlsEntry`：sing-box AnyTLS + 公共 CA 可信 TLS + ECH，固定监听 TCP 443；
- `ShadowsocksLanding`：sing-box Shadowsocks 2022 多用户落地；
- `MonitorOnly`：只配置管理入口、防火墙和可选 Komari；
- `AuditOnly`：只建立临时管理访问并审计。

新部署仍用单一 `Role` 选择初始模块。实例进入协议生命周期管理后，`Role` 只表示当前主角色（规划阶段可暂时表示本次执行目标），实际共存状态以 `ProtocolInventory` 为准；提交模块会把 `Role` 收口为启用的入口角色，若没有入口则使用已启用 Shadowsocks，全部停用时为 `MonitorOnly`。

Schema 3 新计划把运行数据放在 `<InstanceDirectory>/MXH-VPS-Deploy`，`Paths.InstanceDirectory` 指向用户实例目录，`Paths.Archive` 指向受管子目录，`Paths.KeyDirectory` 指向其下 `ssh`。旧 schema 的根目录布局仍按计划原值读取，不自动迁移。

`SshKey.Mode` 为 `ReuseExisting` 或 `GenerateManaged`。复用模式复制私钥并用 `ssh-keygen -y` 推导公钥；它不会修改源文件或轮换服务器 `authorized_keys`。源私钥与受管副本都可作为真实认证候选，前一份被 OpenSSH 拒绝时会尝试后一份。项目不建立额外的 `.ssh` 运行副本；只对实际使用的受管私钥文件设置 Windows OpenSSH 所需的当前用户独占 ACL，其他归档文件和目录不调整权限。Import 的 `EnforceKeyOnlySsh` 是显式用户选择而非纳管前置条件。

`bootstrap-access` 先尝试实例管理私钥，失败后才进入服务商初始认证。密码输入由 OpenSSH 直接处理且不回显，真实的初始登录失败允许重试。若初始密码会话成功，但 Debian 服务商镜像的有效配置禁用了公钥认证、使用非标准 `AuthorizedKeysFile` 或限定了 `AuthenticationMethods`，模块会写入最小的 `00-00-mxh-bootstrap-access.conf`，仅恢复标准公钥入口。该临时兼容配置必须通过 `sshd -t`、`sshd -T` 和 reload，失败即回滚；它不会提前关闭密码或移除服务商端口。最终 key-only 策略仍由 `ssh-transition` 提交。

导入实例不会伪造或保存未知的现有 admin 密码。最终验收对项目管理的密码继续执行真实 `sudo -S`；对标记为 `<not-managed>` 的导入账户，则分别验证 admin 公钥登录和 root 视角的 sudo 授权策略，并明确说明没有验证未知密码本身。

`deployment-baseline`（Order 5）在恢复公钥已验证、其他新机模块尚未修改服务器时建立统一快照。它只记录项目管理的 SSH、协议、证书、nftables、sysctl、Komari、服务状态和受管账户，并记录基线时已有的软件包及 `/root/vps-deploy-backups` 子目录。`deployment-baseline-commit`（Order 119）只有在 AuditOnly 的 `audit` 或常规角色的 `ssh-cutover` 成功后才删除基线；即使通过 `-OnlyModule` 显式调用也不能绕过该门禁。

最终私有归档的 `SHA256SUMS-private.txt` 覆盖静态计划、状态、密钥与配置快照；持续追加的根目录 `deployment.log` 明确不纳入清单，否则任何后续只读审计或维护记录都会使已经完成的归档立即出现伪校验失败。

供应商专有 IPv6 获取、策略路由或网络命名空间应作为单独模块加入，不应修改通用 `sing-box-shadowsocks` 模块。

`network-tuning` 使用计划中的 `NetworkTuning.Mode/BandwidthMbps/ReferenceRttMs` 和初始审计的实际内存计算参数。标称带宽与代表性 RTT 属于用户输入，禁止通过公网测速或虚拟网卡显示速率自动猜测。

`BaselineOnly` 仍记录服务商标称带宽，但不要求 RTT、不修改缓冲区；`AdaptiveConservative` 在同一标称带宽基础上额外要求 RTT。`TuneNetwork` 将网络调优包装成独立生命周期操作：复用前置审计、远端文件/服务快照、最终验收和提交，但模块白名单不包含 `nftables-transition` 或协议安装模块。

`shadowsocks-self-test.sh` 是落地模块的规范功能测试：TCP 通过 HTTPS 检查真实出口，UDP 通过临时 direct inbound 转发 DNS 查询并校验响应。`shadowsocks-external-probe.sh` 供维护验收使用，会下载并校验固定版本临时核心、复用同一套 TCP/UDP 测试，结束后不保留客户端文件。

可信 TLS 相关模块按顺序拆分：

- `certbot-dns`：验证 Cloudflare Zone Token，签发证书，执行模拟续期并安装唯一的续期计时器和部署 hook；
- `local-https-target`：仅在 Reality 的 `LocalOwnedTls` 模式启用，部署回环 nginx 静态站；
- `sing-box-anytls`：安装固定版本低权限核心、生成 AnyTLS 密码与 ECH 密钥、切换 443 并执行 TCP/UDP/ECH 自测；
- `anytls-client-export`：按 IPv4/IPv6 生成 Mihomo 与 sing-box 完整测试配置，并生成 sing-box 出站和 ECH client config 私有片段。

Reality 计划还记录 `XrayVersionChannel` 与解析后的 `XrayVersion`。`FixedVerified` 使用版本目录的当前基线；`LatestStable` 只接受 XTLS/Xray-core 官方 latest API 返回的非草稿、非预发行数字标签。远端安装始终使用锁定提交且校验 SHA-256 的 Xray-install 脚本，并在安装后核对实际版本。

`anytls-apply-config.sh` 在停止既有 Xray 前记录 active/enabled 状态。AnyTLS 启动或监听验证失败时，会停用失败服务并恢复原 Xray 状态；成功后才解除回滚。服务端配置不启用 `auto_detect_interface`，避免为了普通直连出站给低权限服务额外授予 `CAP_NET_RAW`。

`New-MxhAnyTlsPaddingScheme` 在创建计划时生成 `PerInstanceConservativeV1`：保持协议默认方案的前八包结构，但在受控范围内改变各段长度，单段 TLS plaintext 上限不超过 1100 字节。结果写入部署计划并在继续运行时保持不变。服务端通过 AnyTLS 协议下发 padding scheme，客户端配置不需要也不应复制该数组；缺少字段的旧计划由 `Get-MxhAnyTlsPaddingScheme` 回退到官方默认值。

`anytls-self-test.sh` 会以真实 AnyTLS+ECH 客户端完成 HTTPS、出口 IP 和 UDP DNS 往返。`Invoke-MxhRealClientValidation` 使用项目 vendor 目录内经 SHA-256 校验的稳定版 Mihomo 与 sing-box，对 Reality 的主/救援入口及已配置地址族、AnyTLS 的已配置地址族逐项测试。两个核心都通过各自 SOCKS5 UDP 路径做独立 DNS 往返，不修改桌面客户端、TUN 或系统代理；主测试端点失败时再尝试独立备用端点。若控制机没有原生 IPv6，默认应选择另一台受管 VPS 作为外部探针；也可通过强确认明确跳过本次 IPv6 验收，跳过项会写入私有计划与结果并标记为 `SkippedByUser`，不能视为双栈全部通过。非交互模式不会自行生成跳过记录。语法通过、443 可达或证书可读都不能替代这组功能测试。

内置核心只支持 Windows amd64 控制端，解压目录为被 Git 忽略的 `.cache/client-cores`。正常流程不扫描 PATH、注册表或 Clash Verge AppData。交互式手动跳过必须记录 `SkippedByUser`；非交互流程找不到任一核心即失败。Mihomo Alpha 仅作为显式配置的额外兼容检查。

协议生命周期管理不是重新运行新机向导。为兼容旧计划仍使用 `Migration` 字段，但 schema 2 另外记录 `Operation`、`InitialInventory`、`ValidationInventory`、`FinalInventory` 和 `FinalRole`。其中 inventory 将 installed 与 enabled/active 分开；Reality/AnyTLS 只允许一个 enabled，Shadowsocks 可独立并行。

`Migration.ModuleIds` 对模块集合做白名单筛选，按操作选择步骤：

- `migration-preflight`：复验双 SSH、全部已安装协议配置以及远端 installed/enabled/active 状态没有在确认后变化；
- `migration-arm-rollback`：打包全部受管协议文件，记录三个 systemd 服务状态，备份 nftables/sysctl 并部署独立回滚 timer；
- 目标协议的 target/证书前置模块；回滚必须先于 Certbot、target 和协议写入建立；
- 安装操作运行目标协议服务、网络调优和客户端导出；纯启停使用 `protocol-lifecycle-state`，卸载使用 `protocol-lifecycle-uninstall`；
- `nftables-transition` 使用 `ValidationInventory` 为临时真实测试开放必要端口；
- Shadowsocks 目标额外运行 `migration-shadowsocks-probe`，从另一台白名单入口执行真实 TCP/UDP 探测；
- `final-validation`：按验证阶段实际启用的全部协议检查服务、监听、防火墙和目标真实出口；
- `protocol-lifecycle-final-firewall`：在提交前收口为最终服务组合所需端口；
- `migration-commit`：应用最终 enabled/active 状态、更新 inventory 并撤销 timer；
- `private-archive`：下载全部仍安装协议的配置，记录生命周期状态并重新生成校验和。

变更失败时核心调用 `Invoke-MxhProtocolMigrationRollback` 立即触发回滚；若 SSH 暂时被错误防火墙阻断，systemd timer 仍独立执行。回滚会恢复变更前协议文件和所有服务状态，而不是只启动一个“源角色”。回滚后会清除本次 `Migration.ModuleIds` 的成功/失败记录，确保继续时从新快照重新执行全部变更模块。

备份清理不进入可恢复模块流水线，因为它本身删除恢复材料。交互层只允许清理实例 `migration-backups` 与远端时间戳目录中的 `protocol-lifecycle`/旧 `protocol-migration` 子目录，支持保留最近 N 份；活动 rollback timer 或未完成操作存在时拒绝执行。

现有实例导入逻辑位于 `src/VpsDeploy.Import.ps1`，远端解析器为 `existing-vps-import-audit.sh`。导入不套用新机模块图：现有 OpenSSH 私钥默认复制为 `ssh/id_vps_management` 并直接复验，不轮换服务器公钥；密码引导或人工选择时才生成新 Ed25519。SSH 认证策略默认保持，也可选择 key-only。之后只读识别标准路径中的协议配置，创建 `ProtocolInventory`、私有 secrets 和导入状态。导入计划设置 `Firewall.Mode=PreserveExisting`；相关防火墙模块只做语法检查，不执行 `flush ruleset`。

统一运维中心位于 `src/VpsDeploy.Operations.ps1`。它不是 `modules/*.ps1` 的新机流水线，而是复用计划、SSH、协议清单和统一事务的有界操作集合：

- `Start/Get/Complete/Undo-MxhMaintenanceTransaction`：本地 `maintenance-backups` 与远端 `protocol-lifecycle` 成对快照，20 分钟独立回滚；
- `Get-MxhHealthAudit`：读取脱敏服务/监听/版本/证书/文件哈希并和 `HealthBaseline` 比较；
- 手动恢复、凭据轮换、防火墙、固定资产升级、Komari 和退役：远端修改先建立按组件限定的事务；升级保留现有服务端配置，凭据轮换只修改已识别的凭据字段，并复用真实协议验收；Komari 两个更新入口共用一致性备份、迁移与状态核对；
- SSH 维护单独使用 `mxh-ssh-maintenance-rollback.timer`，因为错误端口或公钥不能依赖普通协议回滚连接；
- 客户端候选由 `scripts/merge_client_authority.py` 使用 ruamel.yaml round-trip 处理 Clash、标准 JSON 处理 sing-box，只写实例 `client-candidates`/`decommission-client-candidate`。

独立客户端设计器位于 `src/VpsDeploy.ClientConfig.ps1`。`templates/client/` 是无个人路径、节点和凭据的完整基础配置；`config/client-layout.default.json` 是通用布局，个人默认写入被 Git 忽略的 `config/client-layout.local.json`。`scripts/build_client_authority.py` 同时读取已纳管私有片段、手动节点和可选现有配置，重写 selector 成员/顺序/default，统一 Shadowsocks 的 `dialer-proxy`/`detour`，并拒绝未知引用和 selector 环。发布层可生成新文件，或在双客户端校验后备份并原子覆盖用户明确选择的独立权威文件；AppData 永远拒绝。

运维远端脚本统一使用 `maintenance-*.sh`。健康审计不得输出配置正文；备份/恢复路径必须解析后严格位于 `/root/vps-deploy-backups`；退役脚本永远不删除 SSH 或操作系统。

## 开发约定

- 远端 Bash 放在 `assets/remote`，必须通过 `bash -n`；
- 远端脚本从 `VPS_PARAM_*` 环境变量读取参数，不从 argv 读取秘密；
- 禁止 `set -x`、打印环境变量或把秘密写入临时日志；
- 修改配置前建立时间戳备份；应用前执行语法检查；
- 模块失败时抛出错误，由核心停止后续模块；
- 幂等优先：重复运行不得无故轮换凭据、端口或覆盖已完成状态；
- 需要特殊供应商脚本的功能，应做成显式模块，不能塞进通用基础模块。
- `-OnlyModule` 不会自动补跑依赖；维护可信 TLS 时必须按证书、服务、客户端导出和最终验收的实际依赖顺序显式执行。

- 通用源码、模板和文档不得硬编码个人盘符、用户名、实例 IP、权威客户端配置或归档目录；个人默认只能进入被 Git 忽略的 `.local.json`；
- 新写入应进入 `Paths.Archive` 指向的实例 `MXH-VPS-Deploy` 子目录，不得把运行产物散落到项目源码；
- 新菜单必须有明确子入口和帮助文本。退出只属于主菜单，子菜单的 9 可以是普通编号，不能被全局解释为退出；
- 修改远端状态的独立功能必须使用事务/回滚或说明为何无法恢复；只读功能不得混入隐式写入。

## 状态与兼容

每完成一个模块，核心更新实例私有目录中的 `deployment-state.json`。继续模式默认跳过已成功模块。维护模式可用 `-OnlyModule` 显式重跑，但会显示风险确认。

继续入口还可以放弃未完成事务。新机统一回滚先执行远端恢复、验证初始 root SSH，再以精确路径删除统一基线和本事务新增的时间戳备份；本地清理最后执行。协议变更必须携带 `BaselineCapturedBeforeMutations=true` 才允许自动放弃。旧计划若已经修改远端但没有该可验证基线，只能继续、人工恢复或服务商重置。

新计划使用受管子目录布局；旧计划按照其 `Paths` 原值继续读取。代码不能只靠目录是否存在推断协议状态，应同时核对计划、状态和远端 inventory。没有计划的既有 VPS 必须走 Import，而不是伪造一个最小 `deployment-plan.json`。

## 验证要求

提交前至少运行：

```powershell
pwsh -File .\Start-VPSDeploy.ps1 -Mode ValidateProject
```

该入口在隔离的 PowerShell 子进程中运行测试，避免导入模块的脚本级变量污染当前交互会话，并统一使用 UTF-8 文本输出。CI 的控制端主流程运行在 Windows；Debian 12/13 容器只验证将发送到 VPS 的 Bash、包名与 OpenSSH 契约。

新增远端功能还应在可牺牲测试 VPS 上完成：预检、备份、实际变更、真实协议测试、提交以及失败回滚。一次成功 DryRun、配置语法或服务监听均不能代替端到端测试。
