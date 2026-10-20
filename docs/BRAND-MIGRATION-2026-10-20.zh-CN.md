# May 全新安装迁移（2026-10-20）

按用户最新要求，项目和应用统一更名为 May，并采用独立的全新安装。GitHub 账号 `mxh110708`、账号资料、作者身份、签名证书和上游归属不变；历史标签、历史附件、校验值和 Git 历史不重写。

## 项目与安装目录

- May Route：`may-route-desktop`、`may-route-dashboard`、`may-route-core`；本次安装到 `C:\Program Files\May Route`，与旧版使用同一上层目录。
- May VPS Deploy：`may-vps-deploy`；本次安装到 `D:\Programs\May VPS Deploy`，与旧版使用同一上层目录。
- May Status：`komari-theme-may-status`，保留中性的主题 short `GlassmorphismEnhanced` 和用户自定义设置。

## 独立身份与数据

Route 的 appId 为 `io.may.route`，拥有独立的安装 GUID、`Software\May\Route` 注册项、`may-route` 应用数据根、`may-route-daemon` 服务与数据根、May 命名管道和安装数据流。Deploy 的 Inno AppId / 互斥体为 `may-vps-deploy-desktop`，私人归档叶目录为 `May-VPS-Deploy`，凭据使用 `May.VPSDeploy.Credentials.v1` 熵及独立的 May 格式名。

旧应用、旧服务、旧安装目录和旧数据不由本次任务卸载或删除，由用户稍后处理。现有配置、字体和实例先备份，再导入新目录；旧凭据仅在本次明确授权的数据迁移中解密并重新加密，不要求新程序保留旧品牌身份。不会把旧服务的运行状态复制成第二个活动代理，也不切换当前代理控制权。

已经部署到 VPS 的远程事务协议和历史文件标记属于运维数据格式；这次应用改名不改动生产 VPS、账号或协议事务。存量源码工作目录保留原物理路径，以免破坏工具链和依赖链接；Git remote / 子模块指向新仓库。

本次可安装更新的授权仅用于此次迁移；后续由用户手动更新。不操作用户鼠标。

后续状态：本地源码根目录已统一为 `F:\Pywork\May-Route` 和 `F:\Pywork\May-VPS-Deploy`。改名后的代码保留与删除结论见 [审计记录](POST-RENAME-AUDIT-2026-10-20.zh-CN.md)；本文件中的一次性迁移过程不作为运行时兼容要求。
