from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path

from .command import render_command
from .softether import SOFTETHER_LOCATIONS, find_softether_directory


@dataclass(frozen=True)
class PlannedStep:
    description: str
    command: tuple[str, ...] | None = None

    def rendered_command(self) -> str | None:
        return render_command(self.command) if self.command else None


def validate_server_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise ValueError("The server address must be a public IPv4 address")
    return str(address)


def build_connection_plan(server_ip: str) -> list[PlannedStep]:
    server_ip = validate_server_ip(server_ip)
    directory = find_softether_directory() or SOFTETHER_LOCATIONS[0]
    vpncmd = str(directory / "vpncmd")
    return [
        PlannedStep("Capture the current gateway, interface, routes, and DNS state"),
        PlannedStep("Acquire the connection lock"),
        PlannedStep("Create durable pending state for crash recovery"),
        PlannedStep(
            "Set the SoftEther account endpoint",
            (
                "sudo",
                vpncmd,
                "localhost",
                "/CLIENT",
                "/CMD",
                "AccountSet",
                "vpngate",
                f"/SERVER:{server_ip}:443",
                "/HUB:VPNGATE",
            ),
        ),
        PlannedStep("Add a host route to the server through the original gateway"),
        PlannedStep(
            "Request a SoftEther connection",
            (
                "sudo",
                vpncmd,
                "localhost",
                "/CLIENT",
                "/CMD",
                "AccountConnect",
                "vpngate",
            ),
        ),
        PlannedStep("Poll until SoftEther reports the Connected state"),
        PlannedStep("Start a renewable IPv4 DHCP lease on vpn_vpn"),
        PlannedStep("Block non-local IPv6 traffic while the IPv4-only VPN is active"),
        PlannedStep(
            "Add owned 0.0.0.0/1 and 128.0.0.0/1 routes through vpn_vpn"
        ),
        PlannedStep("Route the root DNS domain through vpn_vpn with systemd-resolved"),
        PlannedStep("Verify the server route, VPN route, DNS path, and IPv6 policy"),
        PlannedStep("Keep ownership state for disconnect and crash recovery"),
    ]


def build_softether_preparation_plan(server_ip: str) -> list[PlannedStep]:
    server_ip = validate_server_ip(server_ip)
    directory = find_softether_directory() or SOFTETHER_LOCATIONS[0]
    vpncmd = str(directory / "vpncmd")
    base = ("sudo", vpncmd, "localhost", "/CLIENT", "/CMD")
    return [
        PlannedStep(
            "Inspect existing virtual adapters",
            (*base, "NicList"),
        ),
        PlannedStep(
            "Create the vpn virtual adapter only if it does not exist",
            (*base, "NicCreate", "vpn"),
        ),
        PlannedStep(
            "Inspect existing connection accounts",
            (*base, "AccountList"),
        ),
        PlannedStep("Stop without changes if the vpngate account already exists"),
        PlannedStep(
            "Create the vpngate account only if it does not exist",
            (
                *base,
                "AccountCreate",
                "vpngate",
                f"/SERVER:{server_ip}:443",
                "/HUB:VPNGATE",
                "/USERNAME:vpn",
                "/NICNAME:vpn",
            ),
        ),
        PlannedStep(
            "Set the VPN Gate username",
            (*base, "AccountUsernameSet", "vpngate", "/USERNAME:vpn"),
        ),
        PlannedStep(
            "Set the standard VPN Gate password authentication",
            (
                *base,
                "AccountPasswordSet",
                "vpngate",
                "/PASSWORD:vpn",
                "/TYPE:standard",
            ),
        ),
        PlannedStep(
            "Bind the account to the vpn virtual adapter",
            (*base, "AccountNicSet", "vpngate", "/NICNAME:vpn"),
        ),
        PlannedStep(
            "Inspect the prepared account without connecting",
            (*base, "AccountGet", "vpngate"),
        ),
    ]


def build_tunnel_test_plan() -> list[PlannedStep]:
    directory = find_softether_directory() or SOFTETHER_LOCATIONS[0]
    vpncmd = str(directory / "vpncmd")
    base = ("sudo", vpncmd, "localhost", "/CLIENT", "/CMD")
    return [
        PlannedStep("Acquire the exclusive VPN operation lock"),
        PlannedStep("Verify that the vpngate account exists"),
        PlannedStep(
            "Request a SoftEther tunnel connection",
            (*base, "AccountConnect", "vpngate"),
        ),
        PlannedStep(
            "Poll until SoftEther reports an established session",
            (*base, "AccountStatusGet", "vpngate"),
        ),
        PlannedStep(
            "Always disconnect the test tunnel",
            (*base, "AccountDisconnect", "vpngate"),
        ),
        PlannedStep("Leave DHCP, routes, and DNS unchanged"),
    ]
