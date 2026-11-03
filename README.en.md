# May VPS Deploy

A Windows desktop tool for deploying and maintaining Debian VPS instances, proxy services, client configurations and May Monitor. Changes follow a review, verification, private archive and recovery workflow.

[简体中文](README.md) · [Releases](https://github.com/mxh110708/may-vps-deploy/releases/latest) · [English quick start](docs/USER-GUIDE.en.md) · [Documentation](docs/README.md)

## Scope

The supported desktop target is Windows 10 2004 or later / Windows 11 amd64. Remote lifecycle acceptance targets Debian 12/13 amd64. The packaged application bundles .NET, WinUI and its configuration helper; PowerShell, Python and a development SDK are not required for normal desktop use.

This documentation baseline is **v0.9.41**. A repository branch is not proof of the version installed on your computer.

Included [round 28](docs/INBOUND-POLICY-ROUND-28-2026-11-02.zh-CN.md) adds ordered TCP categories and multiple referenced outbounds to independent inbounds, with pinned snapshots, dependency checks, path acceptance and scoped recovery. Application UDP keeps the default outbound. Updating the desktop application does not automatically change deployed services.

Included [round 29](docs/SERVER-STREAM-NEXT-HOPS-ROUND-29-2026-11-02.zh-CN.md) adds bounded VLESS TLS/Reality, Trojan TLS and AnyTLS server next hops, plus supported sing-box WS/gRPC sources. It preserves authentication, verified TLS, ECH and session settings, and extends review, actual acceptance and scoped recovery. Check the fixed-core and peer interoperability matrix before use.

Included [round 30](docs/FORWARDING-WIREGUARD-ROUND-30-2026-11-02.zh-CN.md) supports both adjacent WireGuard segments in a three-host chain, with two independently owned slots per host. Explicit per-port mappings support multiple listeners and targets. Bounded TCP PROXY v1/v2 output requires a compatible TLS target; it never trusts incoming address headers. Dependencies and scoped recovery remain enforced.

Included [round 31](docs/OPERATIONS-RESOURCES-ROUND-31-2026-11-03.zh-CN.md) adds a certificate and operations resource overview with expiration, observation freshness, shared consumers, transitive impact and scoped maintenance entrypoints. Viewing resources does not issue certificates or change services.

[Round 32](docs/CLIENT-BATCH-OUTPUT-ROUND-32-2026-11-03.zh-CN.md) adds reviewed node batch edits, native Mihomo/May Route merge fragments with disclosed upstream dependencies, and credential-free full-configuration export differences. Canceling a review writes nothing; changed sources or targets require a new review. Native fragments retain advanced fields but need the destination configuration's DNS, routing and listeners.

The [round 24 work](docs/CHAIN-WIREGUARD-ROUND-24-2026-11-01.zh-CN.md) lets a three-host chain reuse an accepted WireGuard pair on either adjacent hop. It pins both peers, verifies fresh bidirectional traffic and the complete proxy path, and preserves the independent tunnel during chain removal or compensation. It is included in v0.9.40.

[Round 25](docs/SOURCE-SYNC-ROUND-25-2026-11-01.zh-CN.md) adds opt-in scheduled subscription caching, change notices and reviewed synchronization across schemes and node groups. Fetches do not automatically change schemes or servers. [Round 26](docs/SERVER-RULESETS-ROUND-26-2026-11-01.zh-CN.md) adds versioned server classification snapshots and restoration, using the existing multiple-next-hop and real-path acceptance workflow.

[Shared-host chains](docs/SHARED-CHAINS-ROUND-25-2026-11-01.zh-CN.md) are included as an additional feature, previously mislabeled round 25. Chains retain separate bindings, rule identities and acceptance results. Shared changes revalidate surviving paths and compensate from the current snapshot on failure. Updating a shared forwarding component can briefly interrupt existing connections.

This release includes [round 15 Hysteria2 sharing and port hopping](docs/HYSTERIA2-ROUND-15-2026-10-28.zh-CN.md), [round 16 TUIC v5 inbounds](docs/TUIC-ROUND-16-2026-10-28.zh-CN.md), [round 17 server QUIC next hops](docs/SERVER-QUIC-ROUND-17-2026-10-28.zh-CN.md), [round 18 external WS/gRPC nodes](docs/CLIENT-STREAMS-ROUND-18-2026-10-29.zh-CN.md), [round 20 XHTTP client integration](docs/XHTTP-ROUND-20-2026-10-29.zh-CN.md), and [round 21 dual-family TCP / bounded UDP chains](docs/CHAIN-ROUND-21-2026-10-30.zh-CN.md). XHTTP covers four modes, valid HTTP/TLS/Reality combinations, separate download identities and advanced fields, using matching May Core or an equivalent Mihomo representation. UDP chains require fixed-port Hysteria2 or TUIC. Round 19 remains a historical record of the earlier limited subset. This does not imply that an installed release or every public CDN supports these features.

This release also includes [round 22 WireGuard host-to-host channels](docs/WIREGUARD-ROUND-22-2026-10-30.zh-CN.md): kernel WireGuard, IPv4/IPv6 outer endpoints, private IPv4 peer routes, two-host review and compensation, bidirectional TCP/UDP acceptance and reboot verification. It does not replace existing chains or configure a default-route VPN.

| Area | v0.9.41 capabilities |
| --- | --- |
| Instances | New deployment, adoption of recognized layouts, SSH identity checks, health inspection, maintenance and retirement. |
| Inbounds | Reality, AnyTLS, SS2022, Hysteria2, TUIC v5 and supported XHTTP combinations, with separate listener, user, certificate, outbound and recovery identities. |
| Server paths | TCP/UDP forwarding, real Shadowsocks/SS2022 UDP checks, bounded dual-family TCP / QUIC UDP chains, and WireGuard host-to-host channels. |
| Client profiles | Clash/Mihomo and sing-box generation, source validation, regional groups, routing categories, review and export. |
| Monitoring | Separate May Server/Agent maintenance, HTTPS origin checks, scoped read access and reviewed static theme updates. |
| Recovery | Component-scoped snapshots and reconciliation of uncertain acknowledgements, without blindly replaying writes. |

TUIC and bounded UDP chains remain supported. Provider-specific ATT IPv6 leasing, arbitrary UDP multi-hop, billing and hosted subscriptions remain outside current capabilities. A working Hysteria2 inbound does not make a TCP forwarder support QUIC.

[Round 27](docs/CLIENT-OUTPUT-ROUND-27-2026-11-02.zh-CN.md) completes bounded TUIC v5 and plain TLS VLESS/Trojan URI round trips, direct Base64 list import and native configuration reimport. Advanced fields that cannot be represented still require full configuration export.

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

Reusable node groups are encrypted snapshots. Reuse and manually synchronize them across schemes, with source/version checks before exporting Mihomo, sing-box/May Route or representable share links. See [round 23](docs/CLIENT-GROUPS-ROUND-23-2026-10-30.zh-CN.md). No online subscription hosting or billing is added.
