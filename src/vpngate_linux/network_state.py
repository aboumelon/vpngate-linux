from __future__ import annotations

from dataclasses import dataclass
import re

from .command import CommandResult, CommandRunner
from .connection_plan import PlannedStep, validate_server_ip


VPN_INTERFACE = "vpn_vpn"


class NetworkInspectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkBaseline:
    server_ip: str
    gateway: str
    interface: str
    source_ip: str
    default_routes: tuple[str, ...]
    vpn_ipv4_addresses: tuple[str, ...]
    dns_default_interfaces: tuple[str, ...]


def _require_success(result: CommandResult, action: str) -> str:
    if result.succeeded:
        return result.stdout
    detail = result.stderr or result.stdout or f"exit status {result.returncode}"
    raise NetworkInspectionError(f"{action} failed: {detail}")


def _token_after(tokens: list[str], marker: str) -> str | None:
    try:
        index = tokens.index(marker)
        return tokens[index + 1]
    except (ValueError, IndexError):
        return None


def parse_route_get(output: str) -> tuple[str, str, str]:
    first_line = next((line for line in output.splitlines() if line.strip()), "")
    tokens = first_line.split()
    gateway = _token_after(tokens, "via")
    interface = _token_after(tokens, "dev")
    source_ip = _token_after(tokens, "src")
    if gateway is None or interface is None or source_ip is None:
        raise NetworkInspectionError(
            "The route to the VPN server has no gateway, interface, or source address"
        )
    return gateway, interface, source_ip


def parse_brief_ipv4(output: str) -> tuple[str, ...]:
    first_line = next((line for line in output.splitlines() if line.strip()), "")
    if not first_line:
        return ()
    fields = first_line.split()
    return tuple(field for field in fields[2:] if "." in field and "/" in field)


def parse_dns_default_interfaces(output: str) -> tuple[str, ...]:
    current_interface = None
    default_interfaces = []
    for line in output.splitlines():
        link_match = re.match(r"^Link\s+\d+\s+\(([^)]+)\)", line)
        if link_match:
            current_interface = link_match.group(1)
            continue
        if current_interface and re.match(r"^\s*Default Route:\s+yes\s*$", line):
            default_interfaces.append(current_interface)
    return tuple(default_interfaces)


def inspect_network_baseline(
    server_ip: str,
    *,
    runner: CommandRunner | None = None,
) -> NetworkBaseline:
    server_ip = validate_server_ip(server_ip)
    runner = runner or CommandRunner()
    route_output = _require_success(
        runner.run(("ip", "-4", "route", "get", server_ip), timeout=5),
        "Server route inspection",
    )
    gateway, interface, source_ip = parse_route_get(route_output)
    default_output = _require_success(
        runner.run(("ip", "-4", "route", "show", "default"), timeout=5),
        "Default route inspection",
    )
    vpn_result = runner.run(
        ("ip", "-4", "-brief", "address", "show", VPN_INTERFACE),
        timeout=5,
    )
    vpn_addresses = parse_brief_ipv4(vpn_result.stdout) if vpn_result.succeeded else ()
    dns_output = _require_success(
        runner.run(("resolvectl", "status"), timeout=5),
        "DNS route inspection",
    )
    return NetworkBaseline(
        server_ip=server_ip,
        gateway=gateway,
        interface=interface,
        source_ip=source_ip,
        default_routes=tuple(
            line.strip() for line in default_output.splitlines() if line.strip()
        ),
        vpn_ipv4_addresses=vpn_addresses,
        dns_default_interfaces=parse_dns_default_interfaces(dns_output),
    )


def build_server_route_guard_plan(baseline: NetworkBaseline) -> list[PlannedStep]:
    return [
        PlannedStep("Capture the current route and DNS baseline"),
        PlannedStep(
            "Add a dedicated route for the VPN server through the original gateway",
            (
                "sudo",
                "ip",
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
        PlannedStep("Record ownership so only this route can be removed later"),
        PlannedStep("Leave the default route and DNS unchanged"),
    ]
