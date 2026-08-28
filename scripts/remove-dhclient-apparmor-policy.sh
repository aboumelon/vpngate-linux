#!/usr/bin/env bash

set -euo pipefail

readonly POLICY_DESTINATION="/etc/apparmor.d/vpngate-linux-dhclient"
readonly LOCAL_PROFILE="/etc/apparmor.d/local/sbin.dhclient"
readonly DHCP_PROFILE="/etc/apparmor.d/sbin.dhclient"
readonly INCLUDE_PATTERN='^#include <vpngate-linux-dhclient>$'

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this remover as root with sudo." >&2
    exit 1
fi

if [[ -f "${LOCAL_PROFILE}" ]]; then
    sed -i "\|${INCLUDE_PATTERN}|d" "${LOCAL_PROFILE}"
fi
rm -f "${POLICY_DESTINATION}"

if [[ -f "${DHCP_PROFILE}" ]] && command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser --replace "${DHCP_PROFILE}"
fi

echo "Removed the vpngate-linux dhclient AppArmor policy."
