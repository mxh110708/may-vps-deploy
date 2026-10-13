#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_ACTION:?}"
controller_port="${VPS_PARAM_CONTROLLER_PORT:-25774}"
[[ "$controller_port" =~ ^[0-9]{1,5}$ ]] || exit 1
((10#$controller_port >= 1 && 10#$controller_port <= 65535)) || exit 1

release_url() {
  local repo="$1" fallback_tag="$2" asset="$3" url
  [[ "$VPS_PARAM_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$VPS_PARAM_SHA256" =~ ^[0-9a-f]{64}$ && "$VPS_PARAM_ASSET_NAME" == "$asset" ]]
  url="${VPS_PARAM_DOWNLOAD_URL:-https://github.com/${repo}/releases/download/${fallback_tag}/${asset}}"
  [[ "$url" == "https://github.com/${repo}/releases/download/${VPS_PARAM_VERSION}/${asset}" || "$url" == "https://github.com/${repo}/releases/download/v${VPS_PARAM_VERSION}/${asset}" ]]
  printf '%s' "$url"
}

service_binary() {
  local service="$1"; shift
  local command_line
  command_line="$(systemctl show --property=ExecStart --value "$service")"
  python3 - "$command_line" "$@" <<'PY'
import os,pathlib,re,stat,sys
command,*supported=sys.argv[1:]
match=re.search(r"(?:^|\{\s*)path=(.*?)\s*;",command)
if not match or match.group(1) not in supported: raise SystemExit('Unsupported managed service executable')
binary=pathlib.Path(match.group(1))
for p in (binary,*binary.parents):
    st=p.lstat()
    if stat.S_ISLNK(st.st_mode):raise SystemExit('Linked service executable refused')
    if p==binary and (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=0 or not os.access(p,os.X_OK)):
        raise SystemExit('Service executable ownership refused')
print(binary)
PY
}

verify_running_binary() {
  local service="$1" binary="$2" expected="$3" pid
  for _ in {1..20}; do
    pid="$(systemctl show --property=MainPID --value "$service")"
    if systemctl is-active --quiet "$service" && [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/${pid}/exe" -ef "$binary" ]]; then break; fi
    sleep 1
  done
  systemctl is-active --quiet "$service"
  [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/${pid}/exe" -ef "$binary" ]]
  printf '%s  %s\n' "$expected" "/proc/${pid}/exe" | sha256sum --check --status
}

verify_tunnel_ready() {
  local pid endpoint
  pid="$(systemctl show --property=MainPID --value cloudflared.service)"
  # The managed notify service has a fixed loopback metrics port. Imported
  # simple services may choose a dynamic loopback port: resolve only this PID.
  endpoint="$(ss -H -lntp | python3 -c 'import re,sys
pid=sys.argv[1]
ports=[]
for line in sys.stdin:
    fields=line.split()
    if len(fields)>3 and re.search(r"pid="+re.escape(pid)+r"(?:,|\))",line) and re.fullmatch(r"127\.0\.0\.1:[0-9]+",fields[3]):ports.append(fields[3])
if len(ports)!=1:raise SystemExit("Tunnel loopback metrics listener is ambiguous")
print(ports[0])' "$pid")"
  curl --fail --silent --show-error --connect-timeout 5 --max-time 20 "http://${endpoint}/ready" >/dev/null
}

find_controller_binary() {
  local command_line
  command_line="$(systemctl show --property=ExecStart --value komari.service)"
  python3 - "$command_line" /opt/komari/komari /var/lib/komari/komari /usr/local/bin/komari /usr/bin/komari <<'PY'
import os, pathlib, re, sys
command, *supported = sys.argv[1:]
match = re.search(r"(?:^|\{\s*)path=(.*?)\s*;", command)
if not match or match.group(1) not in supported:
    raise SystemExit("Unsupported Komari service executable; automatic upgrade is refused")
binary = pathlib.Path(match.group(1))
if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
    raise SystemExit("Komari service executable is missing, not executable or symlinked")
print(match.group(1))
PY
}

assert_controller_storage() {
  local working_directory command_line
  systemctl cat komari.service >/dev/null
  find_controller_binary >/dev/null
  working_directory="$(systemctl show --property=WorkingDirectory --value komari.service)"
  command_line="$(systemctl show --property=ExecStart --value komari.service)"
  python3 - "$working_directory" "$command_line" /opt/komari /var/lib/komari <<'PY'
import pathlib, re, shlex, sys
working, command, *supported = sys.argv[1:]
roots = [pathlib.Path(value) for value in supported]
root = pathlib.Path(working)
if not working or root not in roots or root.resolve() != root:
    raise SystemExit("Unsupported Komari working/data directory; use a verified manual backup")
match = re.search(r"argv\[\]=(.*?)\s*;", command)
if not match:
    raise SystemExit("Unable to verify Komari service arguments before backup")
arguments = shlex.split(match.group(1))
database = "./data/komari.db"
database_type = "sqlite"
index = 1
while index < len(arguments):
    argument = arguments[index]
    if argument in ("--database", "-d", "--db-type", "-t"):
        if index + 1 >= len(arguments):
            raise SystemExit("Incomplete Komari database argument")
        if argument in ("--database", "-d"):
            database = arguments[index + 1]
        else:
            database_type = arguments[index + 1]
        index += 1
    elif argument.startswith("--database="):
        database = argument.split("=", 1)[1]
    elif argument.startswith("--db-type="):
        database_type = argument.split("=", 1)[1]
    elif argument.startswith("-d") and len(argument) > 2:
        database = argument[2:].removeprefix("=")
    elif argument.startswith("-t") and len(argument) > 2:
        database_type = argument[2:].removeprefix("=")
    index += 1
if database_type.lower() != "sqlite":
    raise SystemExit("Komari 1.5 supports SQLite; automatic upgrade of this database type is refused")
if not database or database.startswith("file:") or "?" in database or "#" in database:
    raise SystemExit("Unsupported Komari database path or DSN; use a verified manual backup")
database_path = pathlib.Path(database)
resolved = (database_path if database_path.is_absolute() else root / database_path).resolve()
if not any(resolved == allowed or allowed in resolved.parents for allowed in roots):
    raise SystemExit("Komari database is outside the supported snapshot directories; automatic upgrade is refused")
PY
}

validate_controller_archive() {
  python3 - "$1" "${2:-validate}" <<'PY'
import pathlib, tarfile, sys
directories = ("opt/komari", "var/lib/komari")
files = {"etc/systemd/system/komari.service", "etc/systemd/system/cloudflared.service",
         "usr/local/bin/komari", "usr/bin/komari", "usr/local/bin/cloudflared", "usr/bin/cloudflared"}
def allowed(name):
    path = pathlib.PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and (str(path) in files or any(str(path) == root or str(path).startswith(root + "/") for root in directories))
with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if not members: raise SystemExit("Empty Controller archive")
    for member in members:
        if not allowed(member.name) or member.isdev() or member.isfifo(): raise SystemExit("Unsupported Controller archive member")
        if member.issym():
            parent = pathlib.PurePosixPath(member.name).parent
            if not allowed(str(parent / member.linkname)): raise SystemExit("Unsafe Controller archive link")
        if member.islnk() and not allowed(member.linkname): raise SystemExit("Unsafe Controller archive hardlink")
    if sys.argv[2] == "scope":
        names = {str(pathlib.PurePosixPath(member.name)) for member in members}
        tunnel_files = {"etc/systemd/system/cloudflared.service", "usr/local/bin/cloudflared", "usr/bin/cloudflared"}
        includes_tunnel = bool(names & tunnel_files)
        if includes_tunnel and ("etc/systemd/system/cloudflared.service" not in names or not names & (tunnel_files - {"etc/systemd/system/cloudflared.service"})):
            raise SystemExit("Incomplete Cloudflared archive; tunnel unit and executable are required")
        print("true" if includes_tunnel else "false")
PY
}

quarantine_controller_data() {
  local destination="$1" directory leaf
  for directory in /var/lib/komari /opt/komari; do
    [[ ! -e "$directory" && ! -L "$directory" ]] && continue
    [[ -d "$directory" && ! -L "$directory" && "$(readlink -f "$directory")" == "$directory" ]] || return 1
    leaf="${directory#/}"; mv "$directory" "$destination/${leaf//\//-}"
  done
}

verify_controller() {
  local binary code pending body pid
  binary="$(find_controller_binary)"
  [[ "${VPS_PARAM_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  grep -Fq "Komari Monitor ${VPS_PARAM_VERSION}" <<<"$("$binary" --help 2>&1)"
  pending=deferred
  if systemctl is-active --quiet komari.service; then
    for _ in {1..30}; do grep -Fq "127.0.0.1:${controller_port}" <<< "$(ss -H -lnt "sport = :${controller_port}" 2>/dev/null)" && break; sleep 1; done
    grep -Fq "127.0.0.1:${controller_port}" <<< "$(ss -H -lnt "sport = :${controller_port}")"
    pid="$(systemctl show --property=MainPID --value komari.service)"
    [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/${pid}/exe" -ef "$binary" ]]
    code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "http://127.0.0.1:${controller_port}/")"
    [[ "$code" =~ ^(200|302|303|307|308|401|403)$ ]]
    body="$(mktemp)"
    if ! code="$(curl --silent --output "$body" --write-out '%{http_code}' --max-time 10 "http://127.0.0.1:${controller_port}/api/admin/database-migration/auth")"; then rm -f "$body"; return 1; fi
    case "$code" in
      404) pending=false ;;
      200)
        if ! pending="$(python3 - "$body" <<'PY'
import json, sys
body = open(sys.argv[1], encoding="utf-8").read()
# The normal 1.5 SPA router returns index.html for unregistered GET routes.
# HTML alone is not proof of completion: verify the normal version API below.
if body.lstrip().lower().startswith(("<!doctype html", "<html")):
    print("false")
    raise SystemExit(0)
value = json.loads(body)
data = value.get("data") if isinstance(value, dict) else None
if not isinstance(data, dict) or data.get("mode") not in ("legacy_monitoring", "metric_store_restructure"):
    raise SystemExit("Unexpected Komari migration response")
print("true")
PY
        )"
        then rm -f "$body"; return 1; fi
        ;;
      *) rm -f "$body"; echo 'Unable to verify Komari database migration state.' >&2; return 1 ;;
    esac
    if [[ "$pending" == false ]]; then
      if ! code="$(curl --silent --output "$body" --write-out '%{http_code}' --max-time 10 "http://127.0.0.1:${controller_port}/api/version")" || [[ "$code" != 200 ]]; then rm -f "$body"; return 1; fi
      if ! python3 - "$body" "$VPS_PARAM_VERSION" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
data = value.get("data") if isinstance(value, dict) else None
if not isinstance(data, dict) or str(data.get("version", "")).removeprefix("v") != sys.argv[2]:
    raise SystemExit("Normal Komari version API does not confirm the expected version")
PY
      then rm -f "$body"; return 1; fi
    fi
    rm -f "$body"
  fi
  printf 'VPSDEPLOY_KOMARI_MIGRATION_REQUIRED_B64=%s\n' "$(printf '%s' "$pending" | base64 | tr -d '\n')"
}

case "$VPS_PARAM_ACTION" in
  ControllerPreflight) assert_controller_storage ;;
  ControllerVerify) verify_controller ;;
  Status)
    for service in komari-agent.service komari.service cloudflared.service; do
      installed=false; enabled=false; active=false
      systemctl cat "$service" >/dev/null 2>&1 && installed=true
      systemctl is-enabled --quiet "$service" 2>/dev/null && enabled=true
      systemctl is-active --quiet "$service" 2>/dev/null && active=true
      printf '%s=%s,%s,%s\n' "$service" "$installed" "$enabled" "$active"
    done
    ;;
  AgentUninstall)
    systemctl disable --now komari-agent.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/komari-agent.service /usr/local/bin/komari-agent
    rm -rf /etc/komari-agent /var/lib/komari-agent
    systemctl daemon-reload
    ;;
  AgentUpgrade)
    : "${VPS_PARAM_VERSION:?}"; : "${VPS_PARAM_ASSET_NAME:?}"; : "${VPS_PARAM_SHA256:?}"
    [[ "$VPS_PARAM_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$VPS_PARAM_SHA256" =~ ^[0-9a-f]{64}$ ]]
    [[ -s /etc/komari-agent/config.json ]]
    binary="$(service_binary komari-agent.service /usr/local/bin/komari-agent)"
    case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
    [[ "$VPS_PARAM_ASSET_NAME" == "komari-agent-linux-${arch}" ]]
    was_active=false; was_enabled=false
    systemctl is-active --quiet komari-agent.service 2>/dev/null && was_active=true
    systemctl is-enabled --quiet komari-agent.service 2>/dev/null && was_enabled=true
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
    url="$(release_url komari-monitor/komari-agent "$VPS_PARAM_VERSION" "komari-agent-linux-${arch}")"
    curl --fail --location --proto '=https' --proto-redir '=https' --max-filesize 536870912 --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$tmp" "$url"
    printf '%s  %s\n' "$VPS_PARAM_SHA256" "$tmp" | sha256sum --check --status
    if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
    # Agent 1.5.11 has no version command. Never execute a downloaded agent
    # for preflight: its normal entry point may start persistent workers.
    # The pinned release checksum identifies the exact version instead.
    install -o root -g root -m 0755 "$tmp" "$binary"
    printf '%s  %s\n' "$VPS_PARAM_SHA256" "$binary" | sha256sum --check --status
    if [[ "$was_active" == true ]]; then
      systemctl restart komari-agent.service
      verify_running_binary komari-agent.service "$binary" "$VPS_PARAM_SHA256"
    fi
    if [[ "$was_enabled" == false ]]; then systemctl disable komari-agent.service >/dev/null 2>&1 || true; fi
    ;;
  ControllerBackup)
    assert_controller_storage
    stamp="$(date -u +%Y%m%d-%H%M%S)"; output="/root/komari-controller-${stamp}.tar.gz"
    [[ ! -e "$output" ]] || { echo 'Komari backup timestamp collision; retry later.' >&2; exit 1; }
    include_tunnel="${VPS_PARAM_INCLUDE_TUNNEL:-true}"
    [[ "$include_tunnel" == true || "$include_tunnel" == false ]]
    managed=(var/lib/komari opt/komari etc/systemd/system/komari.service usr/local/bin/komari usr/bin/komari)
    if [[ "$include_tunnel" == true ]]; then managed+=(etc/systemd/system/cloudflared.service usr/local/bin/cloudflared usr/bin/cloudflared); fi
    paths=(); for p in "${managed[@]}"; do [[ -e "/$p" ]] && paths+=("$p"); done
    ((${#paths[@]} > 0))
    backup_was_active=false; systemctl is-active --quiet komari.service && backup_was_active=true
    restart_after_backup(){ [[ "$backup_was_active" == false ]] || systemctl start komari.service; }
    trap restart_after_backup EXIT
    if [[ "$backup_was_active" == true ]]; then systemctl stop komari.service; fi
    ! systemctl is-active --quiet komari.service || { echo 'Controller is still running; consistent backup refused.' >&2; exit 1; }
    tar --numeric-owner -czpf "$output" -C / "${paths[@]}"; chmod 0600 "$output"
    restart_after_backup; trap - EXIT
    printf 'VPSDEPLOY_KOMARI_BACKUP_B64=%s\n' "$(printf '%s' "$output" | base64 | tr -d '\n')"
    ;;
  ControllerRestore)
    : "${VPS_PARAM_BACKUP_FILE:?}"
    file="$(readlink -f "$VPS_PARAM_BACKUP_FILE")"
    [[ "$file" =~ ^/root/komari-controller-[0-9]{8}-[0-9]{6}\.tar\.gz$ ]]
    restore_tunnel="$(validate_controller_archive "$file" scope)"
    if [[ -n "${VPS_PARAM_BACKUP_SHA256:-}" ]]; then
      [[ "$VPS_PARAM_BACKUP_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]
      printf '%s  %s\n' "$VPS_PARAM_BACKUP_SHA256" "$file" | sha256sum --check --status
    fi
    for directory in /var/lib/komari /opt/komari; do [[ ! -L "$directory" ]] || exit 1; done
    safety="$(mktemp -d /root/vps-deploy-backups/komari-controller-restore-XXXXXXXX)"; chmod 0700 "$safety"
    current=(); managed_files=(etc/systemd/system/komari.service usr/local/bin/komari usr/bin/komari)
    if [[ "$restore_tunnel" == true ]]; then managed_files+=(etc/systemd/system/cloudflared.service usr/local/bin/cloudflared usr/bin/cloudflared); fi
    for p in var/lib/komari opt/komari "${managed_files[@]}"; do [[ -e "/$p" ]] && current+=("$p"); done
    was_enabled=false; was_active=false; tunnel_was_enabled=false; tunnel_was_active=false
    systemctl is-enabled --quiet komari.service 2>/dev/null && was_enabled=true
    systemctl is-active --quiet komari.service 2>/dev/null && was_active=true
    final_active="${VPS_PARAM_FINAL_ACTIVE:-$was_active}"
    final_enabled="${VPS_PARAM_FINAL_ENABLED:-$was_enabled}"
    [[ "$final_active" == true || "$final_active" == false ]]
    [[ "$final_enabled" == true || "$final_enabled" == false ]]
    if [[ "$restore_tunnel" == true ]]; then
      systemctl is-enabled --quiet cloudflared.service 2>/dev/null && tunnel_was_enabled=true
      systemctl is-active --quiet cloudflared.service 2>/dev/null && tunnel_was_active=true
    fi
    changed=false
    rollback(){
      set +e
      if [[ "$changed" == false ]]; then
        [[ "$was_active" == false ]] || systemctl start komari.service
        [[ "$tunnel_was_active" == false ]] || systemctl start cloudflared.service
        return 0
      fi
      systemctl disable --now komari.service >/dev/null 2>&1
      ! systemctl is-active --quiet komari.service || return 1
      if [[ "$restore_tunnel" == true ]]; then
        systemctl disable --now cloudflared.service >/dev/null 2>&1
        ! systemctl is-active --quiet cloudflared.service || return 1
      fi
      failed="$(mktemp -d "$safety/failed-restore-XXXXXXXX")"
      quarantine_controller_data "$failed" || return 1
      for p in "${managed_files[@]}"; do rm -f "/$p"; done
      [[ ! -f "$safety/current.tar.gz" ]] || tar --numeric-owner -xzpf "$safety/current.tar.gz" -C /
      systemctl daemon-reload
      [[ "$was_enabled" == false ]] || systemctl enable komari.service >/dev/null
      [[ "$was_active" == false ]] || systemctl start komari.service
      [[ "$tunnel_was_enabled" == false ]] || systemctl enable cloudflared.service >/dev/null
      [[ "$tunnel_was_active" == false ]] || systemctl start cloudflared.service
    }
    on_restore_exit(){ local rc=$?; trap - EXIT; if ((rc != 0)); then rollback; fi; exit "$rc"; }
    trap on_restore_exit EXIT
    if [[ "$tunnel_was_active" == true ]]; then systemctl stop cloudflared.service; fi
    if [[ "$was_active" == true ]]; then systemctl stop komari.service; fi
    ! systemctl is-active --quiet komari.service || { echo 'Controller is still running; database restore refused.' >&2; exit 1; }
    ((${#current[@]} == 0)) || tar --numeric-owner -czpf "$safety/current.tar.gz" -C / "${current[@]}"
    changed=true
    previous_data="$(mktemp -d "$safety/previous-data-XXXXXXXX")"; quarantine_controller_data "$previous_data"
    for p in "${managed_files[@]}"; do rm -f "/$p"; done
    tar --numeric-owner -xzpf "$file" -C /; systemctl daemon-reload
    systemctl start komari.service
    for _ in {1..30}; do grep -Fq "127.0.0.1:${controller_port}" <<< "$(ss -H -lnt "sport = :${controller_port}" 2>/dev/null)" && break; sleep 1; done
    grep -Fq "127.0.0.1:${controller_port}" <<< "$(ss -H -lntp "sport = :${controller_port}")"
    code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "http://127.0.0.1:${controller_port}/")"
    [[ "$code" =~ ^(200|302|303|307|308|401|403)$ ]]
    binary="$(find_controller_binary)"; pid="$(systemctl show --property=MainPID --value komari.service)"
    [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/${pid}/exe" -ef "$binary" ]]
    restored_version="$("$binary" --help 2>&1)"
    restored_version="$(sed -nE 's/.*Komari Monitor v?([0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?).*/\1/p' <<<"$restored_version" | head -n 1)"
    [[ -n "$restored_version" ]]
    if [[ "$restore_tunnel" == true ]]; then
      systemctl cat cloudflared.service >/dev/null
      if [[ "$tunnel_was_enabled" == true ]]; then systemctl enable cloudflared.service >/dev/null;
      else systemctl disable cloudflared.service >/dev/null; fi
      if [[ "$final_active" == true && "$tunnel_was_active" == true ]]; then
        systemctl start cloudflared.service
        systemctl is-active --quiet cloudflared.service
      fi
    fi
    if [[ "$final_enabled" == true ]]; then systemctl enable komari.service >/dev/null; else systemctl disable komari.service >/dev/null; fi
    if [[ "$final_active" == false ]]; then systemctl stop komari.service; fi
    if [[ "$final_enabled" == true ]]; then systemctl is-enabled --quiet komari.service; else ! systemctl is-enabled --quiet komari.service; fi
    if [[ "$final_active" == true ]]; then systemctl is-active --quiet komari.service; else ! systemctl is-active --quiet komari.service; fi
    trap - EXIT
    printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$safety" | base64 | tr -d '\n')"
    printf 'VPSDEPLOY_KOMARI_RESTORED_VERSION_B64=%s\n' "$(printf '%s' "$restored_version" | base64 | tr -d '\n')"
    printf 'VPSDEPLOY_KOMARI_RESTORED_SHA256_B64=%s\n' "$(sha256sum "$binary" | cut -d' ' -f1 | tr -d '\n' | base64 | tr -d '\n')"
    ;;
  ControllerUpgrade)
    assert_controller_storage
    : "${VPS_PARAM_VERSION:?}"; : "${VPS_PARAM_ASSET_NAME:?}"; : "${VPS_PARAM_SHA256:?}"
    : "${VPS_PARAM_BACKUP_FILE:?}"
    rollback_backup="$(readlink -f "$VPS_PARAM_BACKUP_FILE")"
    [[ "$rollback_backup" =~ ^/root/komari-controller-[0-9]{8}-[0-9]{6}\.tar\.gz$ ]]; validate_controller_archive "$rollback_backup"
    archive_members="$(tar -tzf "$rollback_backup")"
    if grep -Eq '(^|/)cloudflared(\.service)?$' <<<"$archive_members"; then
      echo 'Controller upgrade requires a controller-only consistent backup.' >&2; exit 1
    fi
    for directory in /var/lib/komari /opt/komari; do [[ ! -L "$directory" ]] || { echo 'Unsupported symlinked Komari data directory.' >&2; exit 1; }; done
    case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
    [[ "$VPS_PARAM_ASSET_NAME" == "komari-linux-${arch}" ]]
    binary="$(service_binary komari.service /opt/komari/komari /var/lib/komari/komari /usr/local/bin/komari /usr/bin/komari)"
    was_active=false; was_enabled=false; systemctl is-active --quiet komari.service && was_active=true; systemctl is-enabled --quiet komari.service 2>/dev/null && was_enabled=true
    tmp="$(mktemp)"; previous="$(mktemp)"; cp -a "$binary" "$previous"
    binary_changed=false
    rollback_upgrade(){
      [[ "$binary_changed" == true ]] || return 0
      systemctl stop komari.service || return 1
      ! systemctl is-active --quiet komari.service || return 1
      local failed_dir directory leaf
      failed_dir="$(mktemp -d /root/vps-deploy-backups/komari-failed-upgrade-XXXXXXXX)"
      chmod 0700 "$failed_dir"
      for directory in /var/lib/komari /opt/komari; do
        [[ -d "$directory" ]] || continue
        [[ ! -L "$directory" && "$(readlink -f "$directory")" == "$directory" ]] || return 1
        leaf="${directory#/}"; mv "$directory" "$failed_dir/${leaf//\//-}"
      done
      tar --numeric-owner -xzpf "$rollback_backup" -C /
      install -o root -g root -m 0755 "$previous" "$binary"
      systemctl daemon-reload
      [[ "$was_active" == false ]] || systemctl start komari.service
      [[ "$was_enabled" == false ]] && systemctl disable komari.service >/dev/null 2>&1 || true
    }
    on_upgrade_exit(){ local rc=$?; trap - EXIT; if ((rc != 0)); then rollback_upgrade; fi; rm -f "$tmp" "$previous"; exit "$rc"; }
    trap on_upgrade_exit EXIT
    url="$(release_url komari-monitor/komari "$VPS_PARAM_VERSION" "komari-linux-${arch}")"
    curl --fail --location --proto '=https' --proto-redir '=https' --max-filesize 536870912 --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$tmp" "$url"
    printf '%s  %s\n' "$VPS_PARAM_SHA256" "$tmp" | sha256sum --check --status
    chmod 0700 "$tmp"
    version_output="$("$tmp" --help 2>&1)"; grep -Eq "Komari Monitor v?${VPS_PARAM_VERSION//./\\.}([^0-9.]|$)" <<<"$version_output"
    if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
    systemctl stop komari.service
    ! systemctl is-active --quiet komari.service || { echo 'Controller is still running; upgrade refused.' >&2; exit 1; }
    binary_changed=true
    install -o root -g root -m 0755 "$tmp" "$binary"
    version_output="$("$binary" --help 2>&1)"; grep -Eq "Komari Monitor v?${VPS_PARAM_VERSION//./\\.}([^0-9.]|$)" <<<"$version_output"
    if [[ "$was_active" == true ]]; then systemctl start komari.service; systemctl is-active --quiet komari.service; fi
    verify_controller
    if [[ "$was_enabled" == false ]]; then systemctl disable komari.service >/dev/null 2>&1 || true; fi
    trap - EXIT; rm -f "$tmp" "$previous"
    ;;
  TunnelUpgrade)
    : "${VPS_PARAM_VERSION:?}"; : "${VPS_PARAM_ASSET_NAME:?}"; : "${VPS_PARAM_SHA256:?}"
    [[ "$(uname -m)" == x86_64 ]]
    binary="$(service_binary cloudflared.service /usr/local/bin/cloudflared /usr/bin/cloudflared)"
    url="$(release_url cloudflare/cloudflared "$VPS_PARAM_VERSION" cloudflared-linux-amd64)"
    was_active=false; was_enabled=false
    systemctl is-active --quiet cloudflared.service 2>/dev/null && was_active=true
    systemctl is-enabled --quiet cloudflared.service 2>/dev/null && was_enabled=true
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
    curl --fail --location --proto '=https' --proto-redir '=https' --max-filesize 536870912 --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$tmp" "$url"
    printf '%s  %s\n' "$VPS_PARAM_SHA256" "$tmp" | sha256sum --check --status
    chmod 0700 "$tmp"
    actual="$("$tmp" --version | awk 'NR==1 {print $3}')"; [[ "${actual#v}" == "$VPS_PARAM_VERSION" ]]
    if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
    install -o root -g root -m 0755 "$tmp" "$binary"
    printf '%s  %s\n' "$VPS_PARAM_SHA256" "$binary" | sha256sum --check --status
    if [[ "$was_active" == true ]]; then
      systemctl restart cloudflared.service
      verify_running_binary cloudflared.service "$binary" "$VPS_PARAM_SHA256"
      verify_tunnel_ready
    else
      ! systemctl is-active --quiet cloudflared.service
    fi
    if [[ "$was_enabled" == false ]]; then ! systemctl is-enabled --quiet cloudflared.service; fi
    # Unit, token file, credentials, routes and persistent configuration are untouched.
    ;;
  TunnelRotate)
    : "${VPS_PARAM_TUNNEL_TOKEN:?}"
    [[ "$VPS_PARAM_TUNNEL_TOKEN" != *[[:space:]]* ]]
    cloudflared_bin="$(command -v cloudflared)"; [[ -x "$cloudflared_bin" ]]
    unit=/etc/systemd/system/cloudflared.service
    token_file=''
    if [[ -f "$unit" ]] && grep -Fq -- '--token-file' "$unit"; then
      grep -Fq -- '--token-file /etc/cloudflared/mxh-token' "$unit"
      grep -Fxq 'Type=notify' "$unit"
      token_file=/etc/cloudflared/mxh-token
      [[ ! -L /etc/cloudflared && -f "$token_file" && ! -L "$token_file" && ! -L "$unit" ]]
      temporary="$(mktemp)"
      trap 'rm -f "$temporary"' EXIT
      printf '%s' "$VPS_PARAM_TUNNEL_TOKEN" > "$temporary"
      if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
      install -o root -g cloudflared -m 0640 "$temporary" "$token_file"
      rm -f "$temporary"; trap - EXIT
    else
      cat > "$unit" <<EOF
[Unit]
Description=Cloudflare Tunnel for Komari
Wants=network-online.target
After=network-online.target komari.service
[Service]
Type=simple
ExecStart=${cloudflared_bin} tunnel --no-autoupdate run --token ${VPS_PARAM_TUNNEL_TOKEN}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF
      chmod 0600 "$unit"
    fi
    systemctl daemon-reload; systemctl enable cloudflared.service >/dev/null
    systemctl restart cloudflared.service
    systemctl is-active --quiet cloudflared.service
    pid="$(systemctl show --property=MainPID --value cloudflared.service)"
    [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/${pid}/exe" -ef "$cloudflared_bin" ]]
    python3 - "/proc/${pid}/cmdline" "$token_file" <<'PY'
import os, pathlib, sys
arguments=pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
expected=os.environ["VPS_PARAM_TUNNEL_TOKEN"].encode()
if sys.argv[2]:
    if pathlib.Path(sys.argv[2]).read_bytes() != expected or not any(arguments[index] == b"--token-file" and arguments[index+1] == sys.argv[2].encode() for index in range(len(arguments)-1)):
        raise SystemExit("Running Cloudflared process does not use the managed token file")
else:
    if not any(arguments[index] == b"--token" and arguments[index+1] == expected for index in range(len(arguments)-1)):
        raise SystemExit("Running Cloudflared process does not use the requested token")
PY
    if [[ -n "$token_file" ]]; then curl --fail --silent --show-error --connect-timeout 5 --max-time 20 http://127.0.0.1:20241/ready >/dev/null; fi
    ;;
  ControllerUninstall)
    systemctl disable --now cloudflared.service komari.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/cloudflared.service /etc/systemd/system/komari.service /usr/local/bin/cloudflared /usr/local/bin/komari /usr/bin/komari /usr/bin/cloudflared
    rm -rf /var/lib/komari /opt/komari
    systemctl daemon-reload
    ;;
  *) exit 1 ;;
esac
printf '%s\n' 'VPSDEPLOY_KOMARI_LIFECYCLE_OK'
