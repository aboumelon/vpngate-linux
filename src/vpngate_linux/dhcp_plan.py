from __future__ import annotations

from pathlib import Path

from .connection_plan import PlannedStep
from .network_state import NetworkBaseline
from .softether import SOFTETHER_LOCATIONS, find_softether_directory


RUNTIME_DIRECTORY = Path("/run/vpngate-linux")
DHCLIENT_CONFIG_SOURCE = Path("packaging/dhcp/vpngate-dhclient.conf")
DHCLIENT_CONFIG = RUNTIME_DIRECTORY / "dhclient-address-only.conf"
DHCLIENT_HOOK = RUNTIME_DIRECTORY / "dhclient-address-only"
DHCLIENT_LEASE = RUNTIME_DIRECTORY / "dhclient.leases"
DHCLIENT_PID = RUNTIME_DIRECTORY / "dhclient.pid"


def build_dhcp_test_plan(
    baseline: NetworkBaseline,
    *,
    project_root: Path,
) -> list[PlannedStep]:
    directory = find_softether_directory() or SOFTETHER_LOCATIONS[0]
    vpncmd = str(directory / "vpncmd")
    source_config = str(project_root / DHCLIENT_CONFIG_SOURCE)
    return [
        PlannedStep("Acquire the exclusive VPN operation lock"),
        PlannedStep("Capture and preserve the original route and DNS baseline"),
        PlannedStep(
            "Add the owned VPN server route through the original gateway",
            (
                "sudo",
                "ip",
                "-4",
                "route",
                "add",
                f"{baseline.server_ip}/32",
                "via",
                baseline.gateway,
                "dev",
                baseline.interface,
                "src",
                baseline.source_ip,
            ),
        ),
        PlannedStep(
            "Connect the prepared SoftEther account",
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
        PlannedStep("Poll until SoftEther reports an established session"),
        PlannedStep(
            f"Stage the restricted DHCP configuration from {source_config}"
        ),
        PlannedStep(
            "Request only an IPv4 address and subnet information",
            (
                "sudo",
                "dhclient",
                "-4",
                "-1",
                "-v",
                "-cf",
                str(DHCLIENT_CONFIG),
                "-lf",
                str(DHCLIENT_LEASE),
                "-pf",
                str(DHCLIENT_PID),
                "-sf",
                str(DHCLIENT_HOOK),
                "vpn_vpn",
            ),
        ),
        PlannedStep("Verify the leased IPv4 address and offered VPN gateway"),
        PlannedStep("Verify that the original default route and DNS are unchanged"),
        PlannedStep("Release and remove the temporary IPv4 lease"),
        PlannedStep("Disconnect the SoftEther account"),
        PlannedStep("Remove only the project-owned VPN server route"),
    ]
