#!/usr/bin/env bash
set -euo pipefail

python3 <<'PY'
import base64
import json
import os
from pathlib import Path
import pwd
import re
import subprocess

def run(*args, check=False):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {args[0]}")
    return result

def service_state(service, binary, config):
    unit = run("systemctl", "cat", service).returncode == 0
    binary_ok = True if binary is None else (Path(binary).is_file() and os.access(binary, os.X_OK))
    config_ok = True if config is None else (Path(config).is_file() and Path(config).stat().st_size > 0)
    installed = unit and binary_ok and config_ok
    partial = (unit or binary_ok or config_ok) and not installed
    return {
        "Installed": installed,
        "Enabled": run("systemctl", "is-enabled", "--quiet", service).returncode == 0,
        "Active": run("systemctl", "is-active", "--quiet", service).returncode == 0,
        "Partial": partial,
        "Service": service,
    }

inventory = {
    "SchemaVersion": 1,
    "RealityEntry": service_state("xray.service", "/usr/local/bin/xray", "/usr/local/etc/xray/config.json"),
    "AnyTlsEntry": service_state("sing-box-anytls.service", "/usr/local/bin/sing-box-anytls", "/etc/sing-box-anytls/config.json"),
    "ShadowsocksLanding": service_state("sing-box.service", "/usr/local/bin/sing-box", "/etc/sing-box/config.json"),
}
native = os.environ.get("VPS_PARAM_NATIVE_IMPORT") == "true"
komari_services = {
    "Agent": service_state("komari-agent.service", "/usr/local/bin/komari-agent", "/etc/komari-agent/config.json"),
    "Controller": service_state("komari.service", None, None),
    "Cloudflared": service_state("cloudflared.service", None, None),
}
for role in ("RealityEntry", "AnyTlsEntry", "ShadowsocksLanding"):
    item = inventory[role]
    if item["Partial"]:
        raise RuntimeError(f"partial managed protocol installation: {role}")
    if (item["Enabled"] or item["Active"]) and not item["Installed"]:
        raise RuntimeError(f"invalid service state: {role}")
if not native and inventory["RealityEntry"]["Enabled"] and inventory["AnyTlsEntry"]["Enabled"]:
    raise RuntimeError("Reality and AnyTLS are both enabled")
if not native and inventory["RealityEntry"]["Active"] and inventory["AnyTlsEntry"]["Active"]:
    raise RuntimeError("Reality and AnyTLS are both active")

sshd = run("sshd", "-T", check=True).stdout.splitlines()
ssh_values = {}
ssh_ports = []
for line in sshd:
    key, _, value = line.partition(" ")
    if key == "port" and value.isdigit():
        ssh_ports.append(int(value))
    elif key in {"passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "permitrootlogin"}:
        ssh_values[key] = value
ssh_ports = sorted(set(ssh_ports))
if not ssh_ports:
    raise RuntimeError("no effective SSH port found")

protocols = {}
if inventory["RealityEntry"]["Installed"]:
    path = Path("/usr/local/etc/xray/config.json")
    config = json.loads(path.read_text(encoding="utf-8"))
    reality_inbounds = []
    for inbound in config.get("inbounds", []):
        stream = inbound.get("streamSettings") or {}
        if inbound.get("protocol") == "vless" and stream.get("security") == "reality":
            reality_inbounds.append(inbound)
    if not reality_inbounds:
        raise RuntimeError("Xray config has no supported VLESS Reality inbound")
    normalized = []
    for inbound in reality_inbounds:
        stream = inbound["streamSettings"]
        reality = stream.get("realitySettings") or {}
        clients = (inbound.get("settings") or {}).get("clients") or []
        if len(clients) != 1:
            raise RuntimeError("Reality import requires one managed client per inbound; multiple clients require manual selection")
        client = clients[0]
        names = reality.get("serverNames") or []
        short_ids = reality.get("shortIds") or []
        target = reality.get("target") or reality.get("dest")
        if not names or not short_ids or not target or not reality.get("privateKey") or not client.get("id"):
            raise RuntimeError("Reality inbound is missing required fields")
        normalized.append({
            "port": int(inbound.get("port")),
            "uuid": str(client["id"]),
            "flow": str(client.get("flow") or ""),
            "private": str(reality["privateKey"]),
            "short": str(short_ids[0]),
            "server_name": str(names[0]),
            "target": str(target),
        })
    first = normalized[0]
    for item in normalized[1:]:
        for key in ("uuid", "flow", "private", "short", "server_name", "target"):
            if item[key] != first[key]:
                raise RuntimeError("Reality inbounds do not share one credential/target set")
    if first["flow"] != "xtls-rprx-vision":
        raise RuntimeError("unsupported Reality flow")
    key_output = run("/usr/local/bin/xray", "x25519", "-i", first["private"], check=True).stdout
    match = re.search(r"(?im)^(?:Password(?:\s*\(PublicKey\))?|Public\s*key)\s*:\s*(\S+)", key_output)
    if not match:
        raise RuntimeError("cannot derive Reality client key")
    ports = sorted({item["port"] for item in normalized})
    primaries = {int(item['port']) for item in reality_inbounds if str(item.get('tag', '')).startswith('reality-primary-')}
    if native and (len(ports) > 2 or len(primaries) > 1):
        raise RuntimeError("ambiguous managed Reality listener identity")
    primary = next(iter(primaries)) if native and primaries else 443 if 443 in ports else ports[0]
    if not native and primary != 443:
        raise RuntimeError("existing Reality primary port must be TCP 443 for managed lifecycle")
    backups = [port for port in ports if port != primary]
    version = run("/usr/local/bin/xray", "version", check=True).stdout.splitlines()[0].split()[1]
    force_ipv4 = "ForceIPv4" in json.dumps(config, separators=(",", ":"))
    protocols["RealityEntry"] = {
        "PrimaryPort": primary,
        "BackupPort": backups[0] if backups else None,
        "TargetAddress": first["target"],
        "TargetHost": first["target"].rsplit(":", 1)[0].strip("[]"),
        "ServerName": first["server_name"],
        "TargetMode": "LocalOwnedTls" if first["target"].startswith(("127.0.0.1:", "[::1]:", "localhost:")) else "ExternalAudited",
        "ForceIpv4Egress": force_ipv4,
        "XrayVersion": version,
        "Secrets": {
            "Uuid": first["uuid"],
            "RealityPrivateKey": first["private"],
            "RealityClientKey": match.group(1),
            "ShortId": first["short"],
        },
    }
    if protocols["RealityEntry"]["TargetMode"] == "LocalOwnedTls":
        protocols["RealityEntry"]["LocalHttpsPort"] = int(first["target"].rsplit(":", 1)[1])

if inventory["AnyTlsEntry"]["Installed"]:
    config = json.loads(Path("/etc/sing-box-anytls/config.json").read_text(encoding="utf-8"))
    inbounds = [item for item in config.get("inbounds", []) if item.get("type") == "anytls"]
    if len(inbounds) != 1 or len(inbounds[0].get("users") or []) != 1:
        raise RuntimeError("unsupported AnyTLS config layout")
    inbound = inbounds[0]
    tls = inbound.get("tls") or {}
    server_name = str(tls.get("server_name") or "")
    if not server_name:
        raise RuntimeError("AnyTLS server_name is missing")
    cert_text = run("openssl", "x509", "-in", "/etc/mxh-tls/anytls/fullchain.pem", "-noout", "-ext", "subjectAltName", check=True).stdout
    names = re.findall(r"DNS:([^,\s]+)", cert_text)
    public_names = [name for name in names if name != server_name]
    if not public_names:
        raise RuntimeError("cannot infer AnyTLS ECH public name")
    ech_config = Path("/etc/sing-box-anytls/ech-config.pem").read_text(encoding="utf-8")
    ech_key = Path("/etc/sing-box-anytls/ech-key.pem").read_text(encoding="utf-8")
    payload = "".join(line.strip() for line in ech_config.splitlines() if not line.startswith("-----"))
    version = run("/usr/local/bin/sing-box-anytls", "version", check=True).stdout.splitlines()[0].split()[2]
    protocols["AnyTlsEntry"] = {
        "Port": int(inbound.get("listen_port")),
        "ServerName": server_name,
        "EchPublicName": public_names[0],
        "PaddingScheme": inbound.get("padding_scheme") or [],
        "ForceIpv4Egress": any(rule.get("ip_version") == 6 and rule.get("action") == "reject" for rule in (config.get("route") or {}).get("rules", [])),
        "SingBoxVersion": version,
        "Secrets": {
            "Password": str(inbound["users"][0]["password"]),
            "EchClientConfigPem": ech_config,
            "EchClientConfigBase64": payload,
            "EchServerKeyPem": ech_key,
        },
    }

if native and (inventory["RealityEntry"]["Enabled"] and inventory["AnyTlsEntry"]["Enabled"] or inventory["RealityEntry"]["Active"] and inventory["AnyTlsEntry"]["Active"]):
    if {item["port"] for item in normalized} & {int(item.get("listen_port", 0)) for item in inbounds}:
        raise RuntimeError("Reality and AnyTLS listener ports conflict")

if inventory["ShadowsocksLanding"]["Installed"]:
    config = json.loads(Path("/etc/sing-box/config.json").read_text(encoding="utf-8"))
    inbounds = [item for item in config.get("inbounds", []) if item.get("type") == "shadowsocks"]
    if len(inbounds) != 1:
        raise RuntimeError("unsupported Shadowsocks config layout")
    inbound = inbounds[0]
    users = inbound.get("users") or []
    if not users or not inbound.get("password"):
        raise RuntimeError("Shadowsocks users or server key are missing")
    if any(item.get("name") not in ("ipv4-client", "ipv6-client") for item in users) or len({item.get("name") for item in users}) != len(users):
        raise RuntimeError("Shadowsocks import requires unique ipv4-client / ipv6-client users")
    secondary = next((item for item in users if item.get("name") == "ipv6-client"), None)
    primary = next((item for item in users if item.get("name") == "ipv4-client"), None)
    if primary is None:
        raise RuntimeError("Shadowsocks ipv4-client is missing")
    ipv6_rules = [rule for rule in (config.get("route") or {}).get("rules", [])
                  if "ipv6-client" in rule.get("auth_user", []) and rule.get("action", "route") in ("", "route")]
    ipv6_outbound = None
    if secondary is not None:
        if len(ipv6_rules) != 1:
            raise RuntimeError("Cannot identify the Shadowsocks IPv6 client's route")
        ipv6_outbound = next((item for item in config.get("outbounds", []) if item.get("tag") == ipv6_rules[0].get("outbound")), None)
        if not ipv6_outbound or ipv6_outbound.get("type") != "direct":
            raise RuntimeError("Unsupported Shadowsocks IPv6 egress layout")
    protocols["ShadowsocksLanding"] = {
        "Port": int(inbound.get("listen_port")),
        "Method": str(inbound.get("method")),
        "SecondaryIpv6Enabled": secondary is not None,
        "SecondaryIpv6Address": (ipv6_outbound or {}).get("inet6_bind_address"),
        "SecondaryBindInterface": (ipv6_outbound or {}).get("bind_interface"),
        "SingBoxVersion": run("/usr/local/bin/sing-box", "version", check=True).stdout.splitlines()[0].split()[2],
        "Secrets": {
            "ServerKey": str(inbound["password"]),
            "PrimaryUserKey": str(primary["password"]),
            "SecondaryUserKey": str(secondary["password"]) if secondary else None,
        },
    }

listeners_tcp = run("ss", "-H", "-lntp", check=True).stdout
listeners_udp = run("ss", "-H", "-lnup", check=True).stdout
if inventory["RealityEntry"]["Installed"]:
    run("/usr/local/bin/xray", "run", "-test", "-config", "/usr/local/etc/xray/config.json", check=True)
    if inventory["RealityEntry"]["Active"]:
        for port in {item["port"] for item in normalized}:
            if f":{port} " not in listeners_tcp or "xray" not in listeners_tcp:
                raise RuntimeError("active Reality listener is missing")
if inventory["AnyTlsEntry"]["Installed"]:
    run("/usr/local/bin/sing-box-anytls", "check", "-c", "/etc/sing-box-anytls/config.json", check=True)
    if inventory["AnyTlsEntry"]["Active"] and f":{protocols['AnyTlsEntry']['Port']} " not in listeners_tcp:
        raise RuntimeError("active AnyTLS listener is missing")
if inventory["ShadowsocksLanding"]["Installed"]:
    run("/usr/local/bin/sing-box", "check", "-c", "/etc/sing-box/config.json", check=True)
    ss_port = protocols["ShadowsocksLanding"]["Port"]
    if inventory["ShadowsocksLanding"]["Active"] and (f":{ss_port} " not in listeners_tcp or f":{ss_port} " not in listeners_udp):
        raise RuntimeError("active Shadowsocks TCP/UDP listener is missing")

os_release = {}
for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        os_release[key] = value.strip().strip('"')
memory_kib = 0
for line in Path("/proc/meminfo").read_text().splitlines():
    if line.startswith("MemTotal:"):
        memory_kib = int(line.split()[1])
        break
nft_present = Path("/etc/nftables.conf").is_file()
nft_valid = not nft_present or run("nft", "-c", "-f", "/etc/nftables.conf").returncode == 0

komari_private = None
komari_config = Path("/etc/komari-agent/config.json")
if komari_services["Agent"]["Installed"] and komari_config.is_file():
    parsed = json.loads(komari_config.read_text(encoding="utf-8"))
    komari_private = {"Endpoint": str(parsed.get("endpoint") or ""), "Token": str(parsed.get("token") or "")}
try:
    admin_entry = pwd.getpwnam("admin")
    managed_admin = admin_entry.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false") and Path(admin_entry.pw_dir).is_dir()
except KeyError:
    managed_admin = False
audit = {
    "OsId": os_release.get("ID", ""),
    "OsVersion": os_release.get("VERSION_ID", ""),
    "Architecture": run("uname", "-m", check=True).stdout.strip(),
    "AdminUser": "admin" if managed_admin else "root",
    "MemoryKiB": memory_kib,
    "SshPorts": ssh_ports,
    "PasswordAuthentication": ssh_values.get("passwordauthentication", ""),
    "KbdInteractiveAuthentication": ssh_values.get("kbdinteractiveauthentication", ""),
    "PubkeyAuthentication": ssh_values.get("pubkeyauthentication", ""),
    "PermitRootLogin": ssh_values.get("permitrootlogin", ""),
    "NftablesPresent": nft_present,
    "NftablesValid": nft_valid,
    "ManagedCertbot": Path("/etc/systemd/system/mxh-certbot-renew.timer").is_file() and Path("/usr/local/libexec/mxh-certbot-deploy").is_file(),
    "ProtocolInventory": inventory,
    "Komari": komari_services,
}
private = {"Audit": audit, "Protocols": protocols, "KomariAgent": komari_private}
for name, value in (("IMPORT_AUDIT", audit), ("IMPORT_PRIVATE", private)):
    payload = json.dumps(value, separators=(",", ":")).encode()
    print(f"VPSDEPLOY_{name}_B64=" + base64.b64encode(payload).decode())
PY

printf '%s\n' 'VPSDEPLOY_EXISTING_IMPORT_OK'
