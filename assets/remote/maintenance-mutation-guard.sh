#!/usr/bin/env bash
# Included in remote payloads, not a standalone service. Read-only checks do not
# acquire this lock. A write phase keeps the rollback actor out until it exits.
vps_transaction_check() {
  [[ -n "${VPS_PARAM_EXPECTED_TRANSACTION:-}" ]] || return 0
  local expected="$VPS_PARAM_EXPECTED_TRANSACTION" deadline
  [[ "$expected" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/(protocol-lifecycle|ssh-maintenance)$ ]] || return 1
  [[ "$(cat /var/lib/mxh-vps-deploy/transaction.owner)" == "$expected" ]] || { echo 'Transaction owner changed; mutation refused.' >&2; return 1; }
  [[ ! -e "$expected/rollback-executed" && ! -e "$expected/transaction-committed" ]] || return 1
  deadline="$(cat "$expected/deadline-epoch")"
  [[ "$deadline" =~ ^[0-9]+$ && "$(date +%s)" -lt "$deadline" ]] || { echo 'Rollback deadline passed; mutation refused.' >&2; return 1; }
}

vps_begin_mutation() {
  [[ -n "${VPS_PARAM_EXPECTED_TRANSACTION:-}" ]] || return 0
  exec 8>/var/lib/mxh-vps-deploy/transaction.lock
  flock -w 10 8 || { echo 'Another transaction actor is writing; mutation refused.' >&2; return 1; }
  vps_transaction_check || return 1
  export VPS_TRANSACTION_LOCK_HELD=true
}
