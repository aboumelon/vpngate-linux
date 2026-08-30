#!/usr/bin/env bash

set -euo pipefail

readonly USER_BIN_DIR="${VPNGATE_LAUNCHER_BIN_DIR:-${HOME}/.local/bin}"
readonly APPLICATION_DIR="${VPNGATE_LAUNCHER_APPLICATION_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/applications}"

if [[ ${EUID} -eq 0 ]]; then
    echo "Run this launcher remover as your normal desktop user." >&2
    exit 1
fi

rm -f -- \
    "${USER_BIN_DIR}/vpngate" \
    "${USER_BIN_DIR}/vpngate-gui" \
    "${APPLICATION_DIR}/vpngate-linux.desktop"

desktop_directory="${VPNGATE_LAUNCHER_DESKTOP_DIR:-}"
if [[ -z "${desktop_directory}" ]] && command -v xdg-user-dir >/dev/null 2>&1; then
    desktop_directory="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
elif [[ -z "${desktop_directory}" && -d "${HOME}/Desktop" ]]; then
    desktop_directory="${HOME}/Desktop"
fi
if [[ -n "${desktop_directory}" && -d "${desktop_directory}" && "${desktop_directory}" != "${HOME}" ]]; then
    rm -f -- "${desktop_directory}/vpngate-linux.desktop"
fi

echo "Removed the vpngate user launchers."
