#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_PUBLIC_KEY:?}"

umask 077
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
if ! grep -qxF "$VPS_PARAM_PUBLIC_KEY" /root/.ssh/authorized_keys; then
  [[ ! -s /root/.ssh/authorized_keys ]] || printf '\n' >> /root/.ssh/authorized_keys
  printf '%s\n' "$VPS_PARAM_PUBLIC_KEY" >> /root/.ssh/authorized_keys
fi

managed=/etc/ssh/sshd_config.d/00-00-mxh-bootstrap-access.conf
effective="$(sshd -T)"
needs_update=0
grep -qx 'pubkeyauthentication yes' <<<"$effective" || needs_update=1
grep -Eq '^authorizedkeysfile .*\.ssh/authorized_keys([[:space:]]|$)' <<<"$effective" || needs_update=1
grep -qx 'authenticationmethods any' <<<"$effective" || needs_update=1

if [[ "$needs_update" -eq 1 ]]; then
  install -d -m 755 /etc/ssh/sshd_config.d
  backup="$(mktemp)"
  had_managed=0
  if [[ -f "$managed" ]]; then
    cp -a "$managed" "$backup"
    had_managed=1
  fi
  restore_managed() {
    if [[ "$had_managed" -eq 1 ]]; then cp -a "$backup" "$managed"; else rm -f "$managed"; fi
  }
  cleanup_bootstrap() { rm -f "$backup"; }
  trap cleanup_bootstrap EXIT

  cat > "$managed" <<'VPSDEPLOY_SSH_EOF'
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
AuthenticationMethods any
VPSDEPLOY_SSH_EOF
  chmod 644 "$managed"
  if ! sshd -t; then
    restore_managed
    sshd -t >/dev/null 2>&1 || true
    exit 41
  fi

  effective="$(sshd -T)"
  if ! grep -qx 'pubkeyauthentication yes' <<<"$effective" ||
     ! grep -Eq '^authorizedkeysfile .*\.ssh/authorized_keys([[:space:]]|$)' <<<"$effective" ||
     ! grep -qx 'authenticationmethods any' <<<"$effective"; then
    restore_managed
    sshd -t >/dev/null 2>&1 || true
    exit 42
  fi
  if ! (systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service); then
    restore_managed
    sshd -t >/dev/null 2>&1 || true
    systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service 2>/dev/null || true
    exit 43
  fi
  printf 'VPSDEPLOY_BOOTSTRAP_SSH_CONFIG=updated\n'
else
  printf 'VPSDEPLOY_BOOTSTRAP_SSH_CONFIG=preserved\n'
fi

printf 'VPSDEPLOY_BOOTSTRAP_OK\n'
