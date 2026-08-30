#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VPNGATE_EXECUTABLE="${PROJECT_ROOT}/.venv/bin/vpngate"
readonly USER_BIN_DIR="${VPNGATE_LAUNCHER_BIN_DIR:-${HOME}/.local/bin}"
readonly APPLICATION_DIR="${VPNGATE_LAUNCHER_APPLICATION_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/applications}"
readonly COMMAND_LAUNCHER="${USER_BIN_DIR}/vpngate"
readonly GUI_LAUNCHER="${USER_BIN_DIR}/vpngate-gui"
readonly DESKTOP_ENTRY="${APPLICATION_DIR}/vpngate-linux.desktop"

if [[ ${EUID} -eq 0 ]]; then
    echo "Run this launcher installer as your normal desktop user." >&2
    exit 1
fi

if [[ ! -x "${VPNGATE_EXECUTABLE}" ]]; then
    echo "The project environment is missing; run uv sync first." >&2
    exit 1
fi

install -d -m 0755 "${USER_BIN_DIR}" "${APPLICATION_DIR}"

write_command_launcher() {
    local target="$1"
    local mode="$2"
    local temporary_file
    temporary_file="$(mktemp "${USER_BIN_DIR}/.vpngate-launcher.XXXXXX")"
    trap 'rm -f -- "${temporary_file}"' RETURN

    printf '%s\n' '#!/usr/bin/env bash' >"${temporary_file}"
    if [[ "${mode}" == "gui" ]]; then
        printf 'exec sudo %q gui\n' "${VPNGATE_EXECUTABLE}" >>"${temporary_file}"
    else
        printf 'exec %q "$@"\n' "${VPNGATE_EXECUTABLE}" >>"${temporary_file}"
    fi
    chmod 0755 "${temporary_file}"
    mv -f -- "${temporary_file}" "${target}"
    trap - RETURN
}

write_command_launcher "${COMMAND_LAUNCHER}" command
write_command_launcher "${GUI_LAUNCHER}" gui

escaped_gui_launcher="${GUI_LAUNCHER//\\/\\\\}"
escaped_gui_launcher="${escaped_gui_launcher//\"/\\\"}"
desktop_temporary="$(mktemp "${APPLICATION_DIR}/.vpngate-desktop.XXXXXX")"
trap 'rm -f -- "${desktop_temporary}"' EXIT
{
    printf '%s\n' '[Desktop Entry]'
    printf '%s\n' 'Type=Application'
    printf '%s\n' 'Version=1.0'
    printf '%s\n' 'Name=VPN Gate Linux'
    printf '%s\n' 'Comment=Safe VPN Gate connection manager'
    printf 'Exec="%s"\n' "${escaped_gui_launcher}"
    printf '%s\n' 'Icon=network-vpn'
    printf '%s\n' 'Terminal=true'
    printf '%s\n' 'Categories=Network;Utility;'
    printf '%s\n' 'Keywords=VPN;SoftEther;VPN Gate;'
} >"${desktop_temporary}"
install -m 0644 "${desktop_temporary}" "${DESKTOP_ENTRY}"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APPLICATION_DIR}" >/dev/null 2>&1 || true
fi

desktop_directory="${VPNGATE_LAUNCHER_DESKTOP_DIR:-}"
if [[ -z "${desktop_directory}" ]] && command -v xdg-user-dir >/dev/null 2>&1; then
    desktop_directory="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
elif [[ -z "${desktop_directory}" && -d "${HOME}/Desktop" ]]; then
    desktop_directory="${HOME}/Desktop"
fi

if [[ -n "${desktop_directory}" && -d "${desktop_directory}" && "${desktop_directory}" != "${HOME}" ]]; then
    desktop_shortcut="${desktop_directory}/vpngate-linux.desktop"
    install -m 0755 "${DESKTOP_ENTRY}" "${desktop_shortcut}"
    if command -v gio >/dev/null 2>&1; then
        gio set "${desktop_shortcut}" metadata::trusted true >/dev/null 2>&1 || true
    fi
    echo "Desktop shortcut: ${desktop_shortcut}"
fi

echo "Command launcher: ${COMMAND_LAUNCHER}"
echo "Application launcher: ${DESKTOP_ENTRY}"
echo "If vpngate is not found, add ${USER_BIN_DIR} to PATH or open a new terminal."
