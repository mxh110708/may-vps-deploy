# 独立主机存活检查

独立 watchdog 运行于 Server 之外的主机，通过已核验的公网 HTTPS 地址、固定的 Server 安装 UUID 及专用只读授权读取快照。它不能替代各 Agent 的节点探测，也不将管理员 Key 当成读取令牌。与生产 Server 同机的测试，只能证明进程隔离，不能覆盖整机失联。

## 文件和权限

使用与已发布 Server 对应的 Linux amd64 二进制，校对 Release 附件的 SHA-256 后放到 `/usr/local/lib/may-monitor-watchdog/may-monitor-server`。该目录及文件由 root 管理，目录 0755、程序 0755。不要从开发分支在线执行安装脚本。

单独创建 `may-monitor-watchdog` 系统账户，无登录 shell，不加入其他服务组。应用以下固定目录，拒绝复用来源不明的已有账户、服务、符号链接或文件：

| 路径 | 用途和权限 |
| --- | --- |
| `/etc/may-monitor-watchdog/watchdog.json` | 不含令牌的目标、安装 UUID、确认次数；root 所有、0644 |
| `/etc/may-monitor-watchdog/read-access.env` | 仅含 `MAY_MONITOR_WATCHDOG_READ_TOKEN`；root 所有、0600，由 systemd 读取 |
| `/var/lib/may-monitor-watchdog` | 专用账户所有、0700；状态和可选私密 SMTP 配置 |
| `/etc/systemd/system/may-monitor-watchdog.service` | root 所有、0644；采用仓库[受限单元](../templates/monitor/may-monitor-watchdog.service) |

配置示例全部使用占位符：

```json
{
  "endpoint": "https://monitor.example.com",
  "server_instance_id": "<VERIFIED_SERVER_UUID>",
  "delivery": "none",
  "local_receiver": "",
  "interval_seconds": 30,
  "confirm": 3,
  "recover": 2
}
```

默认每 30 秒检查一次；已经证明健康后，连续三次异常确认故障、两次健康确认恢复。一次请求最多八秒，DNS／连接超时会延长实际确认时间，不能把三次检查说成精确 90 秒 SLA。凭据拒绝、TLS 错误、身份变化和普通失联保留不同状态。工作负载限制为 2% CPU、64 MiB 内存和 32 个任务，不向业务进程注入配置。

首次安装前记录主机身份、既有 SSH／代理／Tunnel／Docker 的主进程及单元散列。安装后通过 `/proc/<MainPID>/exe` 核验真实运行程序，核对服务启用状态、资源限制及 `state.json` 的 `armed: true`、`status: healthy` 和持续前进的 `checked_at`，最后再次比较既有服务。不应以 `systemctl start` 返回成功作为完成依据。

## 通知和授权维护

`delivery: "none"` 只检查和保留事件状态，不向用户发送通知。改为 `email` 并依照 [Server 邮件手册](https://github.com/mxh110708/may-monitor-server/blob/main/docs/EMAIL.zh-CN.md) 在该主机配置 `notification-smtp.json` 后，才具备独立发信条件。Server 上的 SMTP 文件不会自动复制到 watchdog 主机。

目前只有一份读取授权；与 Deploy 共用时必须保持令牌、节点范围和截止时间一致。续期或轮换先在正常 Server 生命周期事务中应用，更新 Deploy 的加密连接和 watchdog 的 root 私密环境文件，重启这一检查单元，再核对 HTTPS 健康及旧授权拒绝情况。不要另外创建一份授权而假设旧值仍有效。保存的截止时间是实际维护期限；过期后会显示凭据被拒绝，不能继续称为健康检测。

SMTP 配置缺失不影响探测；本次明确暂缓真实发信配置。因此跨主机健康、故障／恢复夹具和加密邮件单元测试，可以分别验收，但不能写成真实邮箱收信完成。

## 故障与恢复

只读检查：

```text
systemctl status may-monitor-watchdog.service --no-pager
systemctl show may-monitor-watchdog.service -p ActiveState,MainPID,MemoryCurrent,MemoryPeak,CPUUsageNSec,MemoryMax,CPUQuotaPerSecUSec
```

私下检查状态文件和授权截止时间，不把文件内容整份粘贴到公开日志。`credential_rejected` 应核对授权和到期，`identity_mismatch` 应重新核验目标安装身份，`tls_error` 应修复证书或时钟；这些错误不能通过改成 HTTP、关闭证书校验或换管理员 Key 来绕开。

配置和程序更新先核对私人归档中的机器身份、已有文件摘要及已发布资产。保留旧程序、配置和单元的受限备份，停止该单元后原子替换自己的文件，启动并验收健康才提交。失败只恢复该单元，不关闭或恢复其他监控、SSH、代理、Tunnel、Docker。

同一状态文件具有 Linux 内核互斥锁；重复进程会被拒绝。异常退出会自动释放锁，保留的 `.lock` 文件无需删除。停用时先禁用并停止该单元，确认自有进程消失，再按私人安装清单删除对应文件；不要递归清理共享 `/etc`、`/usr/local/lib` 或 `/var/lib`。
