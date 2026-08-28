#!/usr/bin/env bash

set -euo pipefail

readonly INSTALL_DIR="/usr/local/vpnclient"
readonly UNIT_NAME="vpngate-vpnclient.service"
readonly UNIT_DESTINATION="/etc/systemd/system/${UNIT_NAME}"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly UNIT_SOURCE="${PROJECT_ROOT}/packaging/systemd/${UNIT_NAME}"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this installer as root with sudo." >&2
    exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: sudo $0 <softether-source-directory>" >&2
    exit 1
fi

readonly SOURCE_DIR="$(realpath "$1")"

for required_file in vpnclient vpncmd hamcore.se2; do
    if [[ ! -f "${SOURCE_DIR}/${required_file}" ]]; then
        echo "Missing required file: ${SOURCE_DIR}/${required_file}" >&2
        exit 1
    fi
done

if systemctl is-active --quiet "${UNIT_NAME}"; then
    systemctl stop "${UNIT_NAME}"
fi

install -d -o root -g root -m 0755 "${INSTALL_DIR}"
install -o root -g root -m 0700 "${SOURCE_DIR}/vpnclient" "${INSTALL_DIR}/vpnclient"
install -o root -g root -m 0755 "${SOURCE_DIR}/vpncmd" "${INSTALL_DIR}/vpncmd"
install -o root -g root -m 0644 "${SOURCE_DIR}/hamcore.se2" "${INSTALL_DIR}/hamcore.se2"

for documentation_file in ReadMeFirst_License.txt ReadMeFirst_Important_Notices_en.txt; do
    if [[ -f "${SOURCE_DIR}/${documentation_file}" ]]; then
        install -o root -g root -m 0644 \
            "${SOURCE_DIR}/${documentation_file}" \
            "${INSTALL_DIR}/${documentation_file}"
    fi
done

install -o root -g root -m 0644 "${UNIT_SOURCE}" "${UNIT_DESTINATION}"
systemctl daemon-reload
systemctl enable --now "${UNIT_NAME}"

echo "Installed and started ${UNIT_NAME}."
