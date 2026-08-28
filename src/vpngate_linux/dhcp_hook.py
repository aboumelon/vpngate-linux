from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, Sequence


VPN_INTERFACE = "vpn_vpn"
DEFAULT_LEASE_STATE = Path("/run/vpngate-linux/dhcp-lease.json")
BOUND_REASONS = {"BOUND", "RENEW", "REBIND", "REBOOT"}
CLEAR_REASONS = {"RELEASE", "EXPIRE", "FAIL"}


class DhcpHookError(RuntimeError):
    pass


def _valid_ipv4(value: str, label: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise DhcpHookError(f"Invalid {label}: {value}") from error
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise DhcpHookError(f"Unsafe {label}: {value}")
    return str(address)


def _prefix_length(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise DhcpHookError(f"Invalid subnet mask: {mask}") from error


def _validated_addresses(value: str) -> list[str]:
    addresses = []
    for item in value.split():
        try:
            addresses.append(str(ipaddress.IPv4Address(item)))
        except ipaddress.AddressValueError:
            continue
    return addresses


def _write_state(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), 0o600)
            json.dump(payload, temporary, indent=2)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise DhcpHookError(f"Could not write DHCP lease state: {error}") from error


def _default_run(args: Sequence[str]) -> int:
    completed = subprocess.run(tuple(args), check=False)
    return completed.returncode


def handle_event(
    environment: Mapping[str, str],
    *,
    run: Callable[[Sequence[str]], int] = _default_run,
    state_path: Path = DEFAULT_LEASE_STATE,
) -> None:
    interface = environment.get("interface", "")
    if interface != VPN_INTERFACE:
        raise DhcpHookError(f"Refusing unexpected interface: {interface or 'missing'}")
    reason = environment.get("reason", "")

    if reason == "PREINIT":
        if run(("ip", "link", "set", "dev", VPN_INTERFACE, "up")) != 0:
            raise DhcpHookError("Could not bring up the VPN interface")
        return

    if reason in BOUND_REASONS:
        address = _valid_ipv4(environment.get("new_ip_address", ""), "lease address")
        prefix = _prefix_length(environment.get("new_subnet_mask", ""))
        if run(
            (
                "ip",
                "-4",
                "address",
                "replace",
                f"{address}/{prefix}",
                "broadcast",
                "+",
                "dev",
                VPN_INTERFACE,
            )
        ) != 0:
            raise DhcpHookError("Could not apply the VPN lease address")
        _write_state(
            state_path,
            {
                "version": 1,
                "interface": VPN_INTERFACE,
                "address": address,
                "prefix_length": prefix,
                "offered_routers": _validated_addresses(
                    environment.get("new_routers", "")
                ),
                "offered_dns_servers": _validated_addresses(
                    environment.get("new_domain_name_servers", "")
                ),
            },
        )
        return

    if reason in CLEAR_REASONS:
        if run(
            ("ip", "-4", "address", "flush", "dev", VPN_INTERFACE, "scope", "global")
        ) != 0:
            raise DhcpHookError("Could not clear the VPN lease address")
        state_path.unlink(missing_ok=True)
        return

    if reason in {"MEDIUM", "ARPCHECK", "ARPSEND", "STOP", "NBI"}:
        return
    if reason == "TIMEOUT":
        raise DhcpHookError("Refusing a cached lease after DHCP timeout")
    raise DhcpHookError(f"Unsupported DHCP event: {reason or 'missing'}")


def main() -> int:
    try:
        handle_event(os.environ)
    except (DhcpHookError, OSError) as error:
        print(f"vpngate DHCP hook failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
