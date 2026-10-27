# Google BBR v3 预编译包维护

固定版在维护者的 Linux 构建机统一编译，完整 Debian amd64 镜像随应用源码和安装包提供。用户 VPS 只接收、校验、安装和重启验收，不下载完整内核源码或安装编译工具。Windows 维护者可使用 WSL2 中的 Debian 构建环境；BERO 也可作为构建机。生成的是 May 项目从官方源码构建的内核，不是 Google 发布的官方二进制。

## 构建输入与隔离

使用 `config/kernel-catalog.json` 固定的官方仓库、提交、源码树和材料摘要。输入采用发行版通用 amd64 配置 `/boot/config-<version>`，不使用只针对本机设备裁剪的 `localmodconfig`。配置保留通用 x86-64、SMP、模块、PCI、initramfs、devtmpfs、ext4、IPv4/IPv6，以及 virtio、AHCI、NVMe、Hyper-V、VMware 存储和网络驱动；启用 fq 与 BBR，关闭调试信息和本机发行版证书路径。

源码通过 HTTPS 从固定 Google 仓库读取，核对完整提交、树、Git 对象和源文件；构建时间标识固定为官方提交时间，用户、主机、内核后缀及包版本固定。清单记录输入和最终配置 SHA256；固定时间戳并不宣称已经通过跨构建机的逐字节可重复构建验证。

构建依赖由维护者在专用开发环境准备，包含 Debian 的 build-essential、bc、bison、flex、libssl-dev、libelf-dev、debhelper、rsync、kmod、cpio、xz-utils、zstd、git、fakeroot。启动工具通过 root 建立 systemd DynamicUser 沙箱，实际 Git 和 make 均非 root 执行，最多 4 个并行任务、CPU 300%、内存 6 GiB、6 小时；剩余磁盘低于 2 GiB 停止。要求开始前至少 20 GiB 可用构建空间。不会安装构建出的内核、改动宿主 GRUB 或重启宿主。

## 生成与纳入项目

在包含本项目公开代码的 Linux 构建副本根目录执行：

```bash
sudo python3 scripts/build-kernel-prebuilt.py start --config /boot/config-$(uname -r)
sudo python3 scripts/build-kernel-prebuilt.py status --id '<返回的构建ID>'
sudo python3 scripts/build-kernel-prebuilt.py export --id '<构建ID>' --output '<尚不存在的导出目录>'
```

启动之后只读取状态，不重复执行 start。导出校验源码、配置、Debian 包身份和产物摘要，并确认宿主运行内核与启动身份未变化。导出失败不覆盖已有目录。

将导出的 `kernel.deb`、`kernel.config`、`input.config`、`build-manifest.json` 放入 `assets/kernel/`。保留其中的来源材料与 GPL 文本。更新 `config/kernel-catalog.json` 的 `Prebuilt`：`File` 固定为 `kernel.deb`，`Sha256`、`Bytes` 来自构建清单，`ManifestSha256` 为实际清单文件摘要。完整 `source.tar.xz` 放在发布材料目录，不进入每个客户端安装目录。该源码包直接从同一提交执行 `git archive` 导出，不混入构建输出或构建机私人文件。

```bash
python3 scripts/check-kernel-prebuilt.py --project . --source-archive <导出目录>/source.tar.xz
```

发布前还需在支持的 Debian 版本验证包安装、initramfs、启动和真实 TCP BBR 版本。独立最小 init 的回环验证不代替完整 Debian 用户空间或 GRUB 恢复验证。不同 CPU 架构、EFI/Secure Boot、DKMS、容器等未支持环境仍由预检拒绝。

## 应用与源码发布

固定包和其清单受应用文件清单管理。桌面审阅绑定源码和包指纹；上传前检查本地完整文件，远端再次核对包身份、大小、SHA256 及 APT 计划，只新增一个镜像。安装与重启分别审阅，保留原有内核和既有事务保护。

正式构建需要传入 `scripts/New-VpsReleasePackage.ps1 -KernelSourceArchive <source.tar.xz>`。打包工具校验完整对应源码摘要，并将其作为独立附件复制到发布目录，纳入 SHA256SUMS。发布应用时须同时发布该源码附件、应用和校验清单；保留构建配置、构建程序与许可文本。开发预览可以省略源码发布附件，但仍验证内置二进制和构建清单。

BBR v3 只提供随应用版本更新的固定预编译包，不提供最新提交选项或 VPS 编译路径。开发机使用 `kernel-source.py`、`kernel-build.py` 与 `build-kernel-prebuilt.py`；服务器仅运行 `kernel-runtime.py` 与 `kernel-engine.py`，两者不含编译或版本查询客户端。新源码版本必须重新预编译、验证、锁定清单后随应用发布。

当前 Google v3 固定提交基于 Linux 6.13.7，不能因上游提交长期未变就宣称具有持续安全维护。原有 VPS 内核仍是默认选项，预编译仅降低构建资源要求，不改变来源或维护状态。

当前固定包的摘要、Debian 12/13 安装启动与回退、应用打包结果及未覆盖边界见 [2026-10-16 验证记录](GOOGLE-BBR-PREBUILT-2026-10-16.zh-CN.md)。
