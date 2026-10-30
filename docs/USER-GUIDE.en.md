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

Unreleased round 15 source adds managed port hopping and standard Hysteria2 share links. Hopping requires the owned nftables scope and provider rules allowing every UDP port, uses the same service listener and validates each alias. The default interval is 30 seconds; custom intervals require full client configuration export. See the [round 15 instructions](HYSTERIA2-ROUND-15-2026-10-28.zh-CN.md).

## TUIC v5 (unreleased source)

Unreleased round 16 adds TUIC v5 in the same independent-inbound editor, using separate UUID/password credentials, verified TLS/SNI and explicit UDP firewall acceptance. The defaults are cubic, native UDP relay, a 10-second heartbeat and a 3-second authentication timeout, with 0-RTT disabled. Both authenticated HTTPS and application UDP must pass before commit. See the [TUIC v5 instructions](TUIC-ROUND-16-2026-10-28.zh-CN.md).

## Server QUIC next hops (unreleased source)

Unreleased round 17 adds Hysteria2/TUIC server next hops for sing-box and native Hysteria2 for the pinned Xray core. Select a saved source in server outbound configuration or independent inbound outbound references. Candidates follow core capabilities; HTTPS alone cannot replace default-path application UDP acceptance. See [server QUIC next hops](SERVER-QUIC-ROUND-17-2026-10-28.zh-CN.md) for mapping and recovery boundaries.

## External WS/gRPC nodes (unreleased source)

Round 18 unreleased source adds external VLESS/Trojan over TLS WebSocket or single-stream gRPC, including import, sharing, paired native output and a dedicated editor. Protocol, transport, Host, SNI and service name remain separate. Unsupported options and paths that the pinned cores cannot represent equivalently are rejected during link conversion; retain their full native configuration. See the [round 18 guide](CLIENT-STREAMS-ROUND-18-2026-10-29.zh-CN.md) for exact limits and isolated acceptance.

## VLESS XHTTP (unreleased source)

Round 20 adds four XHTTP modes: stream-one, stream-up, packet-up and auto. TLS supports HTTP/1.1, HTTP/2 and HTTP/3; Reality uses HTTP/2. Keep UUID, SNI, Host and path separate. TLS references an owned certificate; Reality uses its own target and keys. New inbounds still default to HTTP/2 and stream-one, with explicit mode/version selection and advanced extra review. Managed server outbound remains direct-only.

Client schemes can select native May Core output, equivalent Mihomo output, or both. Native XHTTP validation requires the matching May Core and its source/capability manifest; official sing-box 1.14.2 is not a substitute. Import separate download settings from a complete client source or standard share URI; unrelated servers do not automatically share sessions. Reject lossy links/conversions while retaining full native output. See the [round 20 guide](XHTTP-ROUND-20-2026-10-29.zh-CN.md) for maintenance, certificate/key rotation, core upgrades and scoped recovery.

## Cross-instance chains (unreleased source)

Round 21 extends the existing three-instance topology with IPv6 TCP and IPv4/IPv6 UDP for fixed-port Hysteria2 or TUIC v5 inbounds. Save the validated original exit source first, then open chain management on the front instance and select the family, transport, relay, exit, ports and source whitelist. All three hosts use the same family. The relay permits only the front's actual source `/32` or `/128`.

UDP route selection alone does not prove connectivity: the original QUIC protocol, HTTPS and application UDP return must all pass through the complete chain. Successful chains become reviewed sources in Configuration Design. Lost acknowledgements require reconciliation; recovery compensates only the chain's owned component snapshots, including participants already committed. Port hopping, arbitrary UDP, shared instances and encapsulated tunnels are outside this round. See the [round 21 guide](CHAIN-ROUND-21-2026-10-30.zh-CN.md).

## Private data and recovery

The default `<application>/private/` directory contains instance plans, state, protected credentials, schemes, SSH trust and component backups. Do not treat it as a cache or upload it with a bug report. DPAPI encryption depends on the Windows protection context; copying encrypted files to another account does not prove recoverability.

Before updates, back up the entire private set. Application updates, remote core updates, certificate replacement, monitoring maintenance and client-file export have different scopes. Restore only the matching instance/component/transaction and verify file digests. A controller-only restore must not silently restore a tunnel or proxy.

May Monitor runs independently of the Windows app. Use scoped, expiring read credentials for Deploy, not administrator keys. Email needs a private SMTP configuration plus an explicitly enabled notification channel; deployment alone does not enable real delivery.

## Troubleshooting

For SSH errors, check the actual address, port, host key, current authentication and rescue console. For protocol errors, check listener ownership, credentials, SNI, address family and the real client path. For stale monitoring, check scope, expiry, TLS, installation UUID and advancing reports. Missing data is unknown, not zero load.

For uncertain writes or blocked recovery, retain the operation identity, phase, version, error code and redacted logs. Do not delete transaction records or run an unrelated historical rollback script. See [maintenance](MAINTENANCE.zh-CN.md), [client paths](CLIENT-AND-LINES.zh-CN.md), [monitor operations](MONITOR-OPERATIONS.zh-CN.md) and the [documentation index](README.md).
