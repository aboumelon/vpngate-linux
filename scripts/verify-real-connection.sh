#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VPNGATE="${PROJECT_ROOT}/.venv/bin/vpngate"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this verification as root with sudo." >&2
    exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: sudo $0 <vpn-server-ip>" >&2
    exit 1
fi

if [[ ! -x "${VPNGATE}" ]]; then
    echo "The project virtual environment is not ready: ${VPNGATE}" >&2
    exit 1
fi

readonly SERVER_IP="$1"
cleanup_required=true

cleanup() {
    if [[ ${cleanup_required} == true ]]; then
        echo "Running final managed cleanup..."
        "${VPNGATE}" disconnect --apply || "${VPNGATE}" recover --apply
    fi
}

trap cleanup EXIT INT TERM

"${VPNGATE}" connect "${SERVER_IP}" --apply --timeout 30
"${VPNGATE}" status
"${VPNGATE}" verify
"${VPNGATE}" disconnect --apply

cleanup_required=false
trap - EXIT INT TERM
echo "The real connect, verify, and disconnect cycle completed successfully."
