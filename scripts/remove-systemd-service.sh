#!/usr/bin/env bash

set -euo pipefail

readonly UNIT_NAME="vpngate-vpnclient.service"
readonly UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this command as root with sudo." >&2
    exit 1
fi

if systemctl is-active --quiet "${UNIT_NAME}"; then
    systemctl stop "${UNIT_NAME}"
fi

if systemctl is-enabled --quiet "${UNIT_NAME}" 2>/dev/null; then
    systemctl disable "${UNIT_NAME}"
fi

if [[ -f "${UNIT_PATH}" ]]; then
    rm -- "${UNIT_PATH}"
fi

systemctl daemon-reload
systemctl reset-failed "${UNIT_NAME}" 2>/dev/null || true

echo "Removed ${UNIT_NAME}."
echo "SoftEther files and runtime configuration were preserved in /usr/local/vpnclient."
