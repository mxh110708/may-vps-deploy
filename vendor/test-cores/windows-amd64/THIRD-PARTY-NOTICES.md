# Third-party test cores

This directory contains unmodified official Windows amd64 release archives used only for local configuration and real-protocol acceptance tests. MXH-VPS-Deploy verifies each archive with SHA-256 before extracting it into the ignored `.cache/client-cores/` directory.

## Mihomo

- Project: <https://github.com/MetaCubeX/mihomo>
- Vendored release: `v1.19.32`
- Archive: `mihomo-windows-amd64-v1.19.32.zip`
- License: GNU General Public License v3.0 or later; the license text is included as `MIHOMO-LICENSE.txt`.
- Corresponding source: <https://github.com/MetaCubeX/mihomo/tree/v1.19.32> (tag archive: <https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.32.zip>)

## sing-box

- Project: <https://github.com/SagerNet/sing-box>
- Client validation release: `v1.14.2`, matching the official core version used by May Route `1.14.2-mxh.7`.
- Current client archive: `sing-box-1.14.2-windows-amd64.zip`.
- Obsolete Windows validation ZIPs are not included. Linux 1.14.0 is downloaded only into ignored temporary directories when running the upgrade regression.
- License: GNU General Public License v3.0 or later with the upstream name-use restriction; the upstream license is included inside the official archive.
- Corresponding source: <https://github.com/SagerNet/sing-box/tree/v1.14.2> (tag archive: <https://github.com/SagerNet/sing-box/archive/refs/tags/v1.14.2.zip>).

The corresponding download URLs and SHA-256 digests are recorded in `checksums.json` and `config/versions.json`. These archives are command-line cores, not GUI applications. Runtime validation never reads Clash Verge AppData and never changes the system proxy or TUN state.

## Mihomo GeoData

- Project: <https://github.com/MetaCubeX/meta-rules-dat>
- Release channel: `latest`, published `2026-10-01T01:25:25Z`; exact bytes are pinned by SHA-256 and GitHub asset ID in `checksums.json`, not a mutable latest download URL.
- Files: `mihomo-geodata/GeoSite.dat` and `mihomo-geodata/GeoIP.dat`.
- License: GNU General Public License v3.0; corresponding source and generated-data inputs are available in the upstream repository.

These files are copied into each temporary Mihomo validation directory so authority configurations using `GEOSITE` or `GEOIP` can be checked offline and deterministically.

## May Route public SRS bootstrap data

- Original data project and license: <https://github.com/MetaCubeX/meta-rules-dat>, GNU General Public License v3.0.
- Source bundle: <https://github.com/mxh110708/may-route-desktop/blob/61715f8b20e7e95a068e71b67a80ed058d692774/resources/public-rules-v1.json>, the fixed public bundle shipped with May Route `1.14.2-mxh.7`.
- Files: the five `mxh-route-public-rules/*.srs` assets. Per-file SHA-256 and original public URLs are recorded in `checksums.json`; the whole-bundle hash is in `config/versions.json`.

These unchanged binary rules are used only for isolated offline candidate validation. Exported profiles keep the canonical MetaCubeX remote URLs, download detours and update intervals. No `initial_path` or developer machine path is embedded in portable templates. Official sing-box can download the rules normally; May Route can seed the same rules from its own application resources before the proxy has started.

Use `scripts/Sync-ClientValidationAssets.ps1` to reproduce the cores, GeoData and public rules. `-SourceDirectory <verified-vendor-directory> -Offline` reconstructs missing assets from a release/source copy without network access. `-RepairExisting` explicitly quarantines mismatched files before replacing them. A complete verified set needs no download. If upstream removes an old asset ID, use the vendored bytes from this version; do not substitute rolling latest data with an old hash.
