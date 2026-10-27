# Desktop walkthrough

Baseline: May VPS Deploy v0.9.38 on Windows amd64. The Chinese [full manual](USER-GUIDE.zh-CN.md) covers all current desktop workflows; this guide gives the installation, acceptance and recovery sequence in English.

## Install

Download the installer or portable Windows amd64 ZIP and `SHA256SUMS.txt` from the same Release. Calculate the file hash and compare it with the release record:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '<absolute-path-to-downloaded-installer>'
```

The default installation directory is `C:\Programs\May VPS Deploy`. Existing installations keep their location. Extract a portable package to a persistent writable directory before opening `May-VPS-Deploy.exe`. Runtime dependencies are bundled; development tools are not desktop prerequisites.

## Choose a workflow

| Situation | Workflow |
| --- | --- |
| Fresh dedicated Debian 12/13 amd64 machine | New deployment, after confirming recovery-console access and absence of unrelated workloads. |
| Existing supported service without a Deploy archive | Adopt the existing instance through read-only discovery first. |
| Managed machine needs another component | Instance maintenance / additional installation. |
| A previous operation lost its acknowledgement | Reconcile recovery status before retrying any change. |
| Only client files are needed | Configuration Design; generating candidates does not apply remote changes. |

Prepare current SSH credentials, a verified host fingerprint and the provider's rescue console. A display name is not an SSH identity. Provider security groups and the guest's firewall are separate layers.

## Deploy and accept

1. Fill in the instance and SSH information. Keep source keys unchanged and compare the presented host key with an independent reference where available.
2. Select the components, listeners, trusted sources, users, certificates and outbounds. Shared TCP listeners cannot be active at the same address and port. Hysteria2 needs UDP/QUIC, a certificate matching its SNI and a separately managed authentication password.
3. Review the plan, pinned assets, affected services, archive location, firewall changes and verification steps. Only then apply.
4. Keep the task view open until application or recovery completes. If the connection drops, inspect the recorded transaction and current server state; do not blindly replay it.
5. Verify the new SSH path, actual service/listener ownership and a real request through each affected protocol, user and address family. A TCP connection alone does not prove authentication, UDP or QUIC.
6. In Configuration Design, select the validated source, generate Clash/Mihomo and/or sing-box candidates, run validation, then review export destinations. Loading those files into a client is a separate action.

Hysteria2 rate fields use the client's perspective. Both directions at zero select adaptive BBR; positive rates require both values. Provider UDP rules must also permit the selected listener. See the [protocol implementation and acceptance record](HYSTERIA2-ROUND-14-2026-10-25.zh-CN.md) for limits.

## Private data and recovery

The default `<application>/private/` directory contains instance plans, state, protected credentials, schemes, SSH trust and component backups. Do not treat it as a cache or upload it with a bug report. DPAPI encryption depends on the Windows protection context; copying encrypted files to another account does not prove recoverability.

Before updates, back up the entire private set. Application updates, remote core updates, certificate replacement, monitoring maintenance and client-file export have different scopes. Restore only the matching instance/component/transaction and verify file digests. A controller-only restore must not silently restore a tunnel or proxy.

May Monitor runs independently of the Windows app. Use scoped, expiring read credentials for Deploy, not administrator keys. Email needs a private SMTP configuration plus an explicitly enabled notification channel; deployment alone does not enable real delivery.

## Troubleshooting

For SSH errors, check the actual address, port, host key, current authentication and rescue console. For protocol errors, check listener ownership, credentials, SNI, address family and the real client path. For stale monitoring, check scope, expiry, TLS, installation UUID and advancing reports. Missing data is unknown, not zero load.

For uncertain writes or blocked recovery, retain the operation identity, phase, version, error code and redacted logs. Do not delete transaction records or run an unrelated historical rollback script. See [maintenance](MAINTENANCE.zh-CN.md), [client paths](CLIENT-AND-LINES.zh-CN.md), [monitor operations](MONITOR-OPERATIONS.zh-CN.md) and the [documentation index](README.md).
