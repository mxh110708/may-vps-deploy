#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_ROLE:?}"; : "${VPS_PARAM_VERSION:?}"; : "${VPS_PARAM_ASSET_NAME:?}"; : "${VPS_PARAM_SHA256:?}"
[[ "$VPS_PARAM_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$VPS_PARAM_SHA256" =~ ^[a-f0-9]{64}$ ]]
case "$VPS_PARAM_ROLE" in
  RealityEntry) repo=XTLS/Xray-core; binary=/usr/local/bin/xray; config=/usr/local/etc/xray/config.json; asset=Xray-linux-64.zip;;
  AnyTlsEntry) repo=SagerNet/sing-box; binary=/usr/local/bin/sing-box-anytls; config=/etc/sing-box-anytls/config.json; asset="sing-box-${VPS_PARAM_VERSION}-linux-amd64.tar.gz";;
  ShadowsocksLanding) repo=SagerNet/sing-box; binary=/usr/local/bin/sing-box; config=/etc/sing-box/config.json; asset="sing-box-${VPS_PARAM_VERSION}-linux-amd64.tar.gz";;
  *) exit 1;;
esac
[[ "$(uname -m)" == x86_64 && "$VPS_PARAM_ASSET_NAME" == "$asset" ]]
[[ -f "$binary" && ! -L "$binary" && -f "$config" && ! -L "$config" ]]
[[ "$(stat -c '%h' "$binary")" == 1 && "$(stat -c '%h' "$config")" == 1 ]]
python3 - "$binary" "$config" <<'PY'
import pathlib,stat,sys
for name in sys.argv[1:]:
    path=pathlib.Path(name)
    for p in (path,*path.parents):
        st=p.lstat()
        if stat.S_ISLNK(st.st_mode):raise SystemExit('Linked upgrade path refused')
        if p==path and (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=0):raise SystemExit('Upgrade path ownership refused')
PY
url="${VPS_PARAM_DOWNLOAD_URL:-https://github.com/${repo}/releases/download/v${VPS_PARAM_VERSION}/${asset}}"
[[ "$url" == "https://github.com/${repo}/releases/download/v${VPS_PARAM_VERSION}/${asset}" || "$url" == "https://github.com/${repo}/releases/download/${VPS_PARAM_VERSION}/${asset}" ]]
work="$(mktemp -d)"; phase=download
cleanup(){ local rc=$?; if ((rc != 0)); then printf 'VPSDEPLOY_PROXY_UPGRADE_FAILURE_B64=%s\n' "$(printf '%s' "$phase" | base64 | tr -d '\n')"; fi; rm -rf -- "$work"; }
trap cleanup EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --max-filesize 536870912 --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 --output "$work/package" "$url"
phase=checksum
printf '%s  %s\n' "$VPS_PARAM_SHA256" "$work/package" | sha256sum --check --status
phase=archive
python3 - "$work/package" "$work/program" "$VPS_PARAM_ROLE" "$VPS_PARAM_VERSION" <<'PY'
import pathlib,stat,sys,tarfile,zipfile
source,target,role,version=sys.argv[1:]
if role=='RealityEntry':
    with zipfile.ZipFile(source) as archive:
        entries=[item for item in archive.infolist() if item.filename=='xray']
        if len(entries)!=1 or entries[0].file_size>268435456 or stat.S_ISLNK(entries[0].external_attr>>16): raise SystemExit(1)
        data=archive.read(entries[0])
else:
    with tarfile.open(source,'r:gz') as archive:
        entries=[item for item in archive.getmembers() if item.name=='sing-box-'+version+'-linux-amd64/sing-box']
        if len(entries)!=1 or not entries[0].isfile() or entries[0].size>268435456: raise SystemExit(1)
        data=archive.extractfile(entries[0]).read()
if not data:raise SystemExit(1)
pathlib.Path(target).write_bytes(data)
PY
chmod 0755 "$work/program"
phase=version
if [[ "$VPS_PARAM_ROLE" == RealityEntry ]]; then actual="$("$work/program" version | awk 'NR==1 {print $2}')"; else actual="$("$work/program" version | awk 'NR==1 {print $3}')"; fi
[[ "${actual#v}" == "$VPS_PARAM_VERSION" ]]
phase=configuration
before_config="$(sha256sum "$config" | awk '{print $1}')"
if [[ "$VPS_PARAM_ROLE" == RealityEntry ]]; then XRAY_LOCATION_ASSET=/usr/local/share/xray "$work/program" run -test -config "$config" >/dev/null; else "$work/program" check -c "$config" >/dev/null; fi
[[ "$(sha256sum "$config" | awk '{print $1}')" == "$before_config" ]]
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
phase=install
install -o root -g root -m 0755 "$work/program" "$binary"
cmp --silent "$work/program" "$binary"
printf 'VPSDEPLOY_PROXY_CORE_UPDATED\n'
