#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -eq 0 ]]; then
    echo "Run this installer as your normal user. It will request sudo when needed." >&2
    exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <softether-source-directory>" >&2
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required. Install it before running this local installer." >&2
    exit 1
fi

readonly SOFTETHER_SOURCE="$(realpath "$1")"

echo "Synchronizing the local Python environment..."
uv sync

echo "Installing the audited SoftEther systemd service..."
sudo "${PROJECT_ROOT}/scripts/install-systemd-service.sh" "${SOFTETHER_SOURCE}"

if [[ -f /etc/apparmor.d/sbin.dhclient ]]; then
    echo "Installing the narrow dhclient AppArmor policy..."
    sudo "${PROJECT_ROOT}/scripts/install-dhclient-apparmor-policy.sh"
fi

echo "Installation completed."
echo "Run: ${PROJECT_ROOT}/.venv/bin/vpngate doctor"
echo "Run TUI: sudo ${PROJECT_ROOT}/.venv/bin/vpngate gui"
