# May VPS Deploy

A Windows desktop tool for deploying and maintaining Debian VPS instances, proxy services, client configurations and May Monitor. Changes follow a review, verification, private archive and recovery workflow.

[简体中文](README.md) · [Releases](https://github.com/mxh110708/may-vps-deploy/releases/latest) · [English quick start](docs/USER-GUIDE.en.md) · [Documentation](docs/README.md)

## Scope

The supported desktop target is Windows 10 2004 or later / Windows 11 amd64. Remote lifecycle acceptance targets Debian 12/13 amd64. The packaged application bundles .NET, WinUI and its configuration helper; PowerShell, Python and a development SDK are not required for normal desktop use.

This documentation baseline is **v0.9.38**. A repository branch is not proof of the version installed on your computer.

| Area | Supported behavior |
| --- | --- |
| Instances | New deployment, adoption of recognized layouts, SSH identity checks, health inspection, maintenance and retirement. |
| Inbounds | Reality, AnyTLS, SS2022 and Hysteria2, with separate listener, user, certificate, outbound and recovery identities. |
| Server paths | TCP/UDP forwarding, real Shadowsocks/SS2022 UDP checks, and bounded TCP front → relay → exit orchestration. |
| Client profiles | Clash/Mihomo and sing-box generation, source validation, regional groups, routing categories, review and export. |
| Monitoring | Separate May Server/Agent maintenance, HTTPS origin checks, scoped read access and reviewed static theme updates. |
| Recovery | Component-scoped snapshots and reconciliation of uncertain acknowledgements, without blindly replaying writes. |

Provider-specific ATT IPv6 leasing, TUIC deployment, arbitrary UDP multi-hop, billing and hosted subscriptions are not complete product features. A working Hysteria2 inbound does not make a TCP forwarder support QUIC.

## Start using the desktop app

1. Download the Windows amd64 installer or portable ZIP from this repository's Release, together with its checksums. A source archive is not an application package.
2. Verify the download, install and open May VPS Deploy. The default installer directory is `C:\Programs\May VPS Deploy`; an existing installation keeps its location on update.
3. In Deployment, choose a new instance, adoption or an additional component. Prepare current SSH credentials, a host fingerprint and the provider's recovery console.
4. Review the target, ports, certificates, trusted sources, component scope and archive location before applying.
5. Verify the actual service and protocol path. Generate and validate client candidates before exporting them to your authoritative files.

See the [English walkthrough](docs/USER-GUIDE.en.md), [Chinese operational manual](docs/USER-GUIDE.zh-CN.md), [client and line guide](docs/CLIENT-AND-LINES.zh-CN.md) and [maintenance manual](docs/MAINTENANCE.zh-CN.md). The retained [PowerShell reference](docs/CLI-REFERENCE.zh-CN.md) describes a separate legacy driver, not desktop navigation.

## Related products

Deploy changes servers and stores private maintenance records. [May Monitor](https://github.com/mxh110708/may-monitor-server) collects telemetry, history, probes and alerts; [May Status](https://github.com/mxh110708/may-monitor-theme-status) displays its public status page. [May Route](https://github.com/mxh110708/may-route-desktop) consumes client profiles and manages Windows traffic capture and failover. Monitoring alerts do not automatically authorize route changes.

The default `private/` directory contains credentials, instance state, schemes and recovery material. Treat it as private data, not a disposable cache. Windows DPAPI material is tied to its protection context; copying encrypted files to another user does not establish a working recovery.

For issues, provide exact versions, operation stage, error code and redacted logs. Configuration parsing, service startup, protocol acceptance and long-duration testing are different evidence levels. Historical reports remain dated and do not certify every later version.

See [development and validation](docs/DEVELOPMENT.zh-CN.md), [security](docs/SECURITY.md), [history](docs/HISTORY.md), [changelog](CHANGELOG.md) and [third-party notices](vendor/test-cores/windows-amd64/THIRD-PARTY-NOTICES.md). No separate root project license is currently declared; third-party notices are not a license for the entire project.
