#!/usr/bin/env bash
set -euo pipefail
case "${VPS_PARAM_ACTION:?}" in proof-start|proof-stop|proof) ;; *) exit 1 ;; esac
python3 -c "$VPS_WIREGUARD_PROGRAM" "$VPS_PARAM_ACTION"
printf '%s\n' VPSDEPLOY_WIREGUARD_PROOF_DONE
