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

missing_commands=()
for command_name in uv sudo systemctl resolvectl ip dhclient curl; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        missing_commands+=("${command_name}")
    fi
done
if (( ${#missing_commands[@]} > 0 )); then
    echo "Missing required commands: ${missing_commands[*]}" >&2
    echo "Install the requirements listed in README.md, then run this installer again." >&2
    exit 1
fi

readonly SOFTETHER_SOURCE="$(realpath "$1")"

echo "Synchronizing the local Python environment..."
uv sync --locked

echo "Installing user command and desktop launchers..."
"${PROJECT_ROOT}/scripts/install-user-launchers.sh"

echo "Installing the audited SoftEther systemd service..."
sudo "${PROJECT_ROOT}/scripts/install-systemd-service.sh" "${SOFTETHER_SOURCE}"

if [[ -f /etc/apparmor.d/sbin.dhclient ]]; then
    echo "Installing the narrow dhclient AppArmor policy..."
    sudo "${PROJECT_ROOT}/scripts/install-dhclient-apparmor-policy.sh"
fi

echo "Installation completed."
echo "Run: ${HOME}/.local/bin/vpngate doctor"
echo "Run TUI: ${HOME}/.local/bin/vpngate-gui"
