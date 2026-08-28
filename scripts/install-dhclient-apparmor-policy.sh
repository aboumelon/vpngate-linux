#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly POLICY_SOURCE="${PROJECT_ROOT}/packaging/apparmor/vpngate-linux-dhclient"
readonly POLICY_DESTINATION="/etc/apparmor.d/vpngate-linux-dhclient"
readonly LOCAL_PROFILE="/etc/apparmor.d/local/sbin.dhclient"
readonly DHCP_PROFILE="/etc/apparmor.d/sbin.dhclient"
readonly INCLUDE_LINE="#include <vpngate-linux-dhclient>"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this installer as root with sudo." >&2
    exit 1
fi

if [[ ! -f "${DHCP_PROFILE}" ]]; then
    echo "The Ubuntu dhclient AppArmor profile was not found." >&2
    exit 1
fi

if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "apparmor_parser was not found." >&2
    exit 1
fi

install -o root -g root -m 0644 "${POLICY_SOURCE}" "${POLICY_DESTINATION}"
install -d -o root -g root -m 0755 "$(dirname "${LOCAL_PROFILE}")"
touch "${LOCAL_PROFILE}"
chmod 0644 "${LOCAL_PROFILE}"

if ! grep -Fqx "${INCLUDE_LINE}" "${LOCAL_PROFILE}"; then
    printf '\n%s\n' "${INCLUDE_LINE}" >> "${LOCAL_PROFILE}"
fi

apparmor_parser --replace "${DHCP_PROFILE}"
echo "Installed and loaded the vpngate-linux dhclient AppArmor policy."
