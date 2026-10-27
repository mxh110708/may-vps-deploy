# Google BBR v3 源码材料

`commit.json`、`Makefile` 和 `tcp_bbr.c` 来自 `https://github.com/google/bbr` 的固定 v3 提交；具体提交、源码树与文件 SHA256 见 `config/kernel-catalog.json`。固定包由应用版本维护，不提供在线最新提交选择。

`kernel.deb` 是 May 项目根据上述官方提交预编译的通用 Debian amd64 内核镜像。`input.config` 为 Debian 通用输入配置，`kernel.config` 为实际构建配置；启用通用 x86-64 CPU 和常见虚拟磁盘、网卡、ext4、IPv6、fq、BBR 驱动。`build-manifest.json` 记录源码身份、构建程序指纹、输入和输出配置、包大小、SHA256 及完整对应源码包的摘要；`config/kernel-catalog.json` 锁定清单和安装包摘要。

固定版从应用上传此包到 VPS，远端再次验证，只安装一个镜像，不安装编译依赖。VPS 端不查询浮动提交，也不执行源码构建。产物属于 May 项目构建，不是 Google 或 Debian 发布、签名或提供 LTS 安全维护的二进制发行。

源文件保留各自的版权与 SPDX 声明，GPL-2.0 许可文本随附于 `GPL-2.0.txt`。完整对应源码由维护者构建工具直接通过 `git archive` 从固定提交导出，正式发布时作为独立 `source.tar.xz` 附件与应用一起提供，避免将完整源码放进每台 Windows 安装目录。也可从固定官方提交取得完整源码。构建步骤见 [维护者说明](../../docs/GOOGLE-BBR-PREBUILT.zh-CN.md)，Google 发布说明见 `https://github.com/google/bbr/blob/v3/README.md`。
