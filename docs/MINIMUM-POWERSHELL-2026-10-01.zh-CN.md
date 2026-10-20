# 最低 PowerShell 运行环境验证

日期：2026-10-01。项目兼容下限仍是 PowerShell 7.4；选用仍受维护的 7.4.20 补丁版测试，不改宿主安装或已有生产实例。

## 固定资产和运行方式

版本、官方下载地址及 SHA-256 记录在 `tests/fixtures/powershell74-runtime.json`。初始化只解压到全新临时目录，下载或复用 ZIP 后先验证哈希，再执行精确版本检查；已有目录拒绝覆盖。

```powershell
$runtimeDirectory = .\scripts\Initialize-PowerShell74.ps1 -Destination (Join-Path $PWD '.tmp\powershell74-new')
$runtime = Join-Path $runtimeDirectory 'pwsh.exe'
& $runtime -NoProfile -File .\tests\Run-Tests.ps1 -ProjectRoot $PWD
& $runtime -NoProfile -File .\tests\Test-ClientCompatibility.ps1 -ProjectRoot $PWD
```

本地已有已校验 ZIP 时，增加 `-ArchivePath <ZIP路径>`，无需下载。原系统 PowerShell 保持不变；不要永久修改 PATH，也不要把便携目录覆盖到程序安装位置。

## 本轮结果

- 真实 `7.4.20` 进程完成主回归 799 项断言及入口串联的交互、工作台、SSH 权限、菜单、审计、Python 行为测试。
- 初始化器拒绝错误哈希及现有目标目录的四项回归纳入主入口；成功初始化分支以完整已校验官方 ZIP 验证。
- 同一 7.4.20 进程完成官方 sing-box、Mihomo、May Route 核心与五项离线规则检查；项目构建的两份候选通过，原模板未改。
- 新 CI 使用 Python 3.9／3.13 × runner PowerShell／隔离 7.4.20 四个 Windows 档位，另保留 Debian 12／13 与 shell 检查。
- 2026-10-02，维护提交 `a9886e8` 已推送，[对应 GitHub Actions](https://github.com/mxh110708/may-vps-deploy/actions/runs/37026109431) 的七项检查全部通过；v0.5.3 收录本轮最低运行环境维护。正式发行前还须确认发行提交本身的同一七项矩阵全部通过。

## 证据边界

便携进程和 PATH 选择不能由命令名称推断，必须核对 `$PSVersionTable.PSVersion`。静态配置检查不证明宿主系统代理、TUN、实际业务、生产 systemd、低权限账号或数据库迁移。本轮未重跑真实 VPS 升级，也没有把项目版本自动同步到生产。
