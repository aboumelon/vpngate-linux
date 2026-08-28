#!/usr/bin/env bash

set -euo pipefail

readonly SERVER_IP="219.100.37.180"
readonly ORIGINAL_INTERFACE="original0"
readonly ORIGINAL_ADDRESS="172.20.166.250"
readonly ORIGINAL_GATEWAY="172.20.164.1"
readonly VPN_INTERFACE="vpn_vpn"
readonly VPN_ADDRESS="10.244.91.126"
readonly VPN_GATEWAY="10.244.254.254"
readonly IPV6_TABLE="51820"
readonly IPV6_PRIORITY="50"
readonly IPV6_METRIC="42760"

ip link set lo up
ip link add "${ORIGINAL_INTERFACE}" type dummy
ip link set "${ORIGINAL_INTERFACE}" up
ip -4 address add "${ORIGINAL_ADDRESS}/20" dev "${ORIGINAL_INTERFACE}"
ip -4 route add default via "${ORIGINAL_GATEWAY}" dev "${ORIGINAL_INTERFACE}"

ip link add "${VPN_INTERFACE}" type dummy
ip link set "${VPN_INTERFACE}" up
ip -4 address add "${VPN_ADDRESS}/16" dev "${VPN_INTERFACE}"

ip -4 route add "${SERVER_IP}/32" \
    via "${ORIGINAL_GATEWAY}" \
    dev "${ORIGINAL_INTERFACE}" \
    src "${ORIGINAL_ADDRESS}"
ip -4 route add 0.0.0.0/1 \
    via "${VPN_GATEWAY}" \
    dev "${VPN_INTERFACE}" \
    src "${VPN_ADDRESS}"
ip -4 route add 128.0.0.0/1 \
    via "${VPN_GATEWAY}" \
    dev "${VPN_INTERFACE}" \
    src "${VPN_ADDRESS}"

ip -6 route add unreachable default \
    metric "${IPV6_METRIC}" \
    table "${IPV6_TABLE}"
ip -6 rule add priority "${IPV6_PRIORITY}" lookup "${IPV6_TABLE}"

ip -4 route get 1.1.1.1 | grep -Fq "dev ${VPN_INTERFACE}"
ip -4 route get "${SERVER_IP}" | grep -Fq "dev ${ORIGINAL_INTERFACE}"
ip -4 route show default | grep -Fq "dev ${ORIGINAL_INTERFACE}"
ip -6 rule show priority "${IPV6_PRIORITY}" | grep -Fq "lookup ${IPV6_TABLE}"
ip -6 route show table all | grep -Eq \
    "unreachable default.*metric ${IPV6_METRIC}.*table ${IPV6_TABLE}|unreachable default.*table ${IPV6_TABLE}.*metric ${IPV6_METRIC}"

if ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1; then
    echo "IPv6 unexpectedly has a usable route." >&2
    exit 1
fi

ip -4 route del 0.0.0.0/1 \
    via "${VPN_GATEWAY}" \
    dev "${VPN_INTERFACE}" \
    src "${VPN_ADDRESS}"
ip -4 route del 128.0.0.0/1 \
    via "${VPN_GATEWAY}" \
    dev "${VPN_INTERFACE}" \
    src "${VPN_ADDRESS}"
ip -6 rule del priority "${IPV6_PRIORITY}" lookup "${IPV6_TABLE}"
ip -6 route del unreachable default \
    metric "${IPV6_METRIC}" \
    table "${IPV6_TABLE}"
ip -4 route del "${SERVER_IP}/32" \
    via "${ORIGINAL_GATEWAY}" \
    dev "${ORIGINAL_INTERFACE}" \
    src "${ORIGINAL_ADDRESS}"

ip -4 route get 1.1.1.1 | grep -Fq "dev ${ORIGINAL_INTERFACE}"
test -z "$(ip -4 route show 0.0.0.0/1)"
test -z "$(ip -4 route show 128.0.0.0/1)"
test -z "$(ip -6 rule show priority "${IPV6_PRIORITY}")"

echo "The isolated kernel routing integration test passed."
