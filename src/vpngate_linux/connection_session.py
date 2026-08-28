from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Callable, Literal

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from .command import CommandResult, CommandRunner
from .connection_plan import validate_server_ip
from .dhcp_hook import DEFAULT_LEASE_STATE, VPN_INTERFACE
from .dhcp_plan import (
    DHCLIENT_CONFIG,
    DHCLIENT_CONFIG_SOURCE,
    DHCLIENT_HOOK,
    DHCLIENT_LEASE,
    DHCLIENT_PID,
)
from .lease_test import (
    DhcpLeaseState,
    _load_lease,
    _parse_account_endpoint,
    _write_runtime_config,
    _write_runtime_hook,
)
from .network_state import (
    NetworkBaseline,
    inspect_network_baseline,
    parse_dns_default_interfaces,
)
from .route_guard import (
    RouteGuardStore,
    _protect_server_route_locked,
    _unprotect_server_route_locked,
)
from .softether import find_softether_directory
from .softether_prepare import ACCOUNT_NAME
from .softether_tunnel import (
    CONNECTED_STATUS,
    DEFAULT_LOCK_PATH,
    connection_lock,
)


DEFAULT_SESSION_STATE = Path("/run/vpngate-linux/connection.json")
APPARMOR_DHCLIENT_PROFILE = Path("/etc/apparmor.d/sbin.dhclient")
APPARMOR_PROJECT_POLICY = Path("/etc/apparmor.d/vpngate-linux-dhclient")
IPV4_VPN_ROUTES = ("0.0.0.0/1", "128.0.0.0/1")
IPV6_POLICY_TABLE = 51820
IPV6_RULE_PRIORITY = 50
IPV6_ROUTE_METRIC = 42760


class ConnectionSessionError(RuntimeError):
    pass


class SessionState(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: Literal[1] = 1
    phase: Literal["connecting", "connected", "disconnecting"]
    server_ip: str
    original_gateway: str
    original_interface: str
    original_source_ip: str
    original_default_routes: tuple[str, ...]
    original_dns_default_interfaces: tuple[str, ...]
    vpn_address: str | None = None
    vpn_prefix_length: int | None = None
    vpn_gateway: str | None = None
    vpn_dns_servers: tuple[str, ...] = ()
    server_route_owned: bool = False
    tunnel_requested: bool = False
    dhcp_started: bool = False
    ipv6_block_owned: bool = False
    ipv4_routes_owned: bool = False
    dns_owned: bool = False
    public_ip: str | None = None
    started_at: datetime


class SessionStore:
    def __init__(self, path: Path = DEFAULT_SESSION_STATE) -> None:
        self.path = path

    def load(self) -> SessionState | None:
        if not self.path.exists():
            return None
        try:
            return SessionState.model_validate_json(
                self.path.read_text(encoding="utf-8")
            )
        except (OSError, ValidationError, ValueError) as error:
            raise ConnectionSessionError(
                f"Connection state is invalid: {error}"
            ) from error

    def save(self, state: SessionState) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                os.fchmod(temporary.fileno(), 0o600)
                temporary.write(state.model_dump_json(indent=2))
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, self.path)
        except OSError as error:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise ConnectionSessionError(
                f"Could not save connection state: {error}"
            ) from error

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            raise ConnectionSessionError(
                f"Could not remove connection state: {error}"
            ) from error


@dataclass(frozen=True)
class ConnectionResult:
    server_ip: str
    vpn_address: str
    vpn_gateway: str
    vpn_dns_servers: tuple[str, ...]
    status_checks: int
    public_ip: str | None


@dataclass(frozen=True)
class DisconnectResult:
    had_state: bool
    cleanup_actions: tuple[str, ...]


@dataclass(frozen=True)
class ConnectionStatus:
    state: SessionState | None
    tunnel_connected: bool
    vpn_addresses: tuple[str, ...]
    ipv4_routes_active: bool
    dns_active: bool
    ipv6_block_active: bool
    project_dhclient_processes: int


@dataclass(frozen=True)
class VerificationResult:
    public_ipv4_route: bool
    vpn_server_route: bool
    dns_routing: bool
    dns_query_succeeded: bool
    ipv6_fail_closed: bool
    public_ip: str | None


def _vpncmd_args(directory: Path, command: str, *arguments: str) -> tuple[str, ...]:
    return (
        str(directory / "vpncmd"),
        "localhost",
        "/CLIENT",
        "/CMD",
        command,
        *arguments,
    )


def _detail(result: CommandResult) -> str:
    return result.stderr or result.stdout or f"exit status {result.returncode}"


def _has_token_pair(tokens: list[str], marker: str, value: str) -> bool:
    try:
        return tokens[tokens.index(marker) + 1] == value
    except (ValueError, IndexError):
        return False


def _require_success(result: CommandResult, action: str) -> None:
    if not result.succeeded:
        raise ConnectionSessionError(f"{action} failed: {_detail(result)}")


def _apparmor_is_enabled() -> bool:
    try:
        return Path("/sys/module/apparmor/parameters/enabled").read_text(
            encoding="ascii"
        ).strip().casefold() == "y"
    except OSError:
        return False


def _require_dhclient_policy() -> None:
    if (
        _apparmor_is_enabled()
        and APPARMOR_DHCLIENT_PROFILE.exists()
        and not APPARMOR_PROJECT_POLICY.exists()
    ):
        raise ConnectionSessionError(
            "The vpngate-linux dhclient AppArmor policy is not installed; run "
            "sudo ./scripts/install-dhclient-apparmor-policy.sh"
        )


def _initial_state(baseline: NetworkBaseline) -> SessionState:
    return SessionState(
        phase="connecting",
        server_ip=baseline.server_ip,
        original_gateway=baseline.gateway,
        original_interface=baseline.interface,
        original_source_ip=baseline.source_ip,
        original_default_routes=baseline.default_routes,
        original_dns_default_interfaces=baseline.dns_default_interfaces,
        started_at=datetime.now(UTC),
    )


def _set_account_endpoint(
    runner: CommandRunner,
    directory: Path,
    server_ip: str,
) -> None:
    updated = runner.run(
        _vpncmd_args(
            directory,
            "AccountSet",
            ACCOUNT_NAME,
            f"/SERVER:{server_ip}:443",
            "/HUB:VPNGATE",
        ),
        timeout=15,
    )
    _require_success(updated, "SoftEther endpoint update")
    inspected = runner.run(
        _vpncmd_args(directory, "AccountGet", ACCOUNT_NAME),
        timeout=10,
    )
    _require_success(inspected, "SoftEther account verification")
    endpoint = _parse_account_endpoint(inspected.stdout)
    if endpoint != (server_ip, 443):
        raise ConnectionSessionError(
            f"SoftEther endpoint verification failed: expected {server_ip}:443"
        )


def _connect_tunnel(
    runner: CommandRunner,
    directory: Path,
    *,
    timeout_seconds: int,
    sleeper: Callable[[float], None],
) -> int:
    requested = runner.run(
        _vpncmd_args(directory, "AccountConnect", ACCOUNT_NAME),
        timeout=10,
    )
    _require_success(requested, "SoftEther connection request")
    for attempt in range(1, timeout_seconds + 1):
        status = runner.run(
            _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
            timeout=10,
        )
        if status.succeeded and CONNECTED_STATUS in status.stdout:
            return attempt
        if attempt < timeout_seconds:
            sleeper(1)
    raise ConnectionSessionError(
        f"The SoftEther tunnel was not established within {timeout_seconds} seconds"
    )


def _acquire_persistent_lease(
    runner: CommandRunner,
    project_root: Path,
    *,
    timeout_seconds: int,
) -> DhcpLeaseState:
    config_source = project_root / DHCLIENT_CONFIG_SOURCE
    if not config_source.is_file():
        raise ConnectionSessionError(
            f"DHCP configuration was not found: {config_source}"
        )
    for path in (DEFAULT_LEASE_STATE, DHCLIENT_LEASE, DHCLIENT_PID):
        path.unlink(missing_ok=True)
    _write_runtime_config(config_source, DHCLIENT_CONFIG)
    _write_runtime_hook(DHCLIENT_HOOK)
    acquired = runner.run(
        (
            "dhclient",
            "-4",
            "-v",
            "-cf",
            str(DHCLIENT_CONFIG),
            "-lf",
            str(DHCLIENT_LEASE),
            "-pf",
            str(DHCLIENT_PID),
            "-sf",
            str(DHCLIENT_HOOK),
            VPN_INTERFACE,
        ),
        timeout=timeout_seconds + 10,
    )
    _require_success(acquired, "DHCP lease acquisition")
    try:
        lease = _load_lease(DEFAULT_LEASE_STATE)
    except Exception as error:
        raise ConnectionSessionError(
            f"DHCP did not produce a valid lease state: {error}; "
            f"dhclient output: {_detail(acquired)}"
        ) from error
    if not lease.offered_routers:
        raise ConnectionSessionError("The VPN DHCP server did not offer a gateway")
    if not lease.offered_dns_servers:
        raise ConnectionSessionError("The VPN DHCP server did not offer DNS servers")
    return lease


def _route_matches(
    output: str,
    prefix: str,
    gateway: str,
    address: str,
) -> bool:
    first_line = next((line for line in output.splitlines() if line.strip()), "")
    tokens = first_line.split()
    if not tokens or tokens[0] != prefix:
        return False
    expected = (("via", gateway), ("dev", VPN_INTERFACE), ("src", address))
    for marker, value in expected:
        try:
            if tokens[tokens.index(marker) + 1] != value:
                return False
        except (ValueError, IndexError):
            return False
    return True


def _preflight_ipv4_routes(runner: CommandRunner) -> None:
    for prefix in IPV4_VPN_ROUTES:
        existing = runner.run(("ip", "-4", "route", "show", prefix), timeout=5)
        _require_success(existing, f"Existing route inspection for {prefix}")
        if existing.stdout.strip():
            raise ConnectionSessionError(
                f"A route for {prefix} already exists without project ownership"
            )


def _apply_ipv4_routes(
    runner: CommandRunner,
    *,
    gateway: str,
    address: str,
) -> None:
    for prefix in IPV4_VPN_ROUTES:
        added = runner.run(
            (
                "ip",
                "-4",
                "route",
                "add",
                prefix,
                "via",
                gateway,
                "dev",
                VPN_INTERFACE,
                "src",
                address,
            ),
            timeout=10,
        )
        _require_success(added, f"VPN route creation for {prefix}")
        verified = runner.run(("ip", "-4", "route", "show", prefix), timeout=5)
        _require_success(verified, f"VPN route verification for {prefix}")
        if not _route_matches(verified.stdout, prefix, gateway, address):
            raise ConnectionSessionError(
                f"The created VPN route for {prefix} does not match ownership"
            )


def _preflight_ipv6_block(runner: CommandRunner) -> None:
    rule = runner.run(
        ("ip", "-6", "rule", "show", "priority", str(IPV6_RULE_PRIORITY)),
        timeout=5,
    )
    _require_success(rule, "IPv6 policy rule inspection")
    if rule.stdout.strip():
        raise ConnectionSessionError(
            f"IPv6 rule priority {IPV6_RULE_PRIORITY} is already in use"
        )
    route = runner.run(
        ("ip", "-6", "route", "show", "table", "all"),
        timeout=5,
    )
    _require_success(route, "IPv6 policy table inspection")
    if any(
        f"table {IPV6_POLICY_TABLE}" in line
        for line in route.stdout.splitlines()
    ):
        raise ConnectionSessionError(
            f"IPv6 route table {IPV6_POLICY_TABLE} is already in use"
        )


def _apply_ipv6_block(runner: CommandRunner) -> None:
    added_route = runner.run(
        (
            "ip",
            "-6",
            "route",
            "add",
            "unreachable",
            "default",
            "metric",
            str(IPV6_ROUTE_METRIC),
            "table",
            str(IPV6_POLICY_TABLE),
        ),
        timeout=10,
    )
    _require_success(added_route, "IPv6 blocking route creation")
    added_rule = runner.run(
        (
            "ip",
            "-6",
            "rule",
            "add",
            "priority",
            str(IPV6_RULE_PRIORITY),
            "lookup",
            str(IPV6_POLICY_TABLE),
        ),
        timeout=10,
    )
    _require_success(added_rule, "IPv6 blocking rule creation")
    verified_rule = runner.run(
        ("ip", "-6", "rule", "show", "priority", str(IPV6_RULE_PRIORITY)),
        timeout=5,
    )
    _require_success(verified_rule, "IPv6 blocking rule verification")
    if f"lookup {IPV6_POLICY_TABLE}" not in verified_rule.stdout:
        raise ConnectionSessionError("The IPv6 blocking rule could not be verified")
    verified_route = runner.run(
        ("ip", "-6", "route", "show", "table", "all"),
        timeout=5,
    )
    _require_success(verified_route, "IPv6 blocking route verification")
    if not any(
        "unreachable default" in line and f"table {IPV6_POLICY_TABLE}" in line
        for line in verified_route.stdout.splitlines()
    ):
        raise ConnectionSessionError("The IPv6 blocking route could not be verified")


def _apply_dns(runner: CommandRunner, servers: tuple[str, ...]) -> None:
    operations = (
        ("resolvectl", "dns", VPN_INTERFACE, *servers),
        ("resolvectl", "domain", VPN_INTERFACE, "~."),
        ("resolvectl", "default-route", VPN_INTERFACE, "yes"),
        ("resolvectl", "flush-caches"),
    )
    for operation in operations:
        _require_success(runner.run(operation, timeout=10), "VPN DNS configuration")


def _preflight_dns(runner: CommandRunner) -> None:
    current = runner.run(("resolvectl", "status", VPN_INTERFACE), timeout=5)
    if current.succeeded and (
        "DNS Servers:" in current.stdout
        or "DNS Domain:" in current.stdout
        or "Default Route: yes" in current.stdout
    ):
        raise ConnectionSessionError(
            "vpn_vpn already has DNS configuration without project ownership"
        )


def _verify_connected(
    runner: CommandRunner,
    state: SessionState,
) -> str | None:
    if state.vpn_address is None or state.vpn_gateway is None:
        raise ConnectionSessionError("Connection state has no VPN address or gateway")
    public_route = runner.run(("ip", "-4", "route", "get", "1.1.1.1"), timeout=5)
    _require_success(public_route, "VPN route verification")
    route_tokens = public_route.stdout.split()
    if VPN_INTERFACE not in route_tokens or state.vpn_address not in route_tokens:
        raise ConnectionSessionError("Public IPv4 traffic is not routed through vpn_vpn")
    server_route = runner.run(
        ("ip", "-4", "route", "get", state.server_ip),
        timeout=5,
    )
    _require_success(server_route, "VPN server route verification")
    server_tokens = server_route.stdout.split()
    expected_server_route = (
        ("via", state.original_gateway),
        ("dev", state.original_interface),
        ("src", state.original_source_ip),
    )
    if any(
        not _has_token_pair(server_tokens, marker, value)
        for marker, value in expected_server_route
    ):
        raise ConnectionSessionError("The VPN server route no longer uses the original link")
    defaults = runner.run(("ip", "-4", "route", "show", "default"), timeout=5)
    _require_success(defaults, "Original default route verification")
    observed_defaults = tuple(
        line.strip() for line in defaults.stdout.splitlines() if line.strip()
    )
    if observed_defaults != state.original_default_routes:
        raise ConnectionSessionError("The original IPv4 default route changed unexpectedly")
    dns = runner.run(("resolvectl", "status", VPN_INTERFACE), timeout=5)
    _require_success(dns, "VPN DNS verification")
    if "~." not in dns.stdout or "Default Route: yes" not in dns.stdout:
        raise ConnectionSessionError("The VPN DNS routing domain is not active")
    if any(server not in dns.stdout for server in state.vpn_dns_servers):
        raise ConnectionSessionError("One or more VPN DNS servers are not active")
    global_dns = runner.run(("resolvectl", "status"), timeout=5)
    _require_success(global_dns, "Original DNS interface verification")
    observed_dns_defaults = parse_dns_default_interfaces(global_dns.stdout)
    if any(
        interface not in observed_dns_defaults
        for interface in state.original_dns_default_interfaces
    ):
        raise ConnectionSessionError("The original DNS interface changed unexpectedly")
    ipv6_rule = runner.run(
        ("ip", "-6", "rule", "show", "priority", str(IPV6_RULE_PRIORITY)),
        timeout=5,
    )
    _require_success(ipv6_rule, "IPv6 leak policy verification")
    if f"lookup {IPV6_POLICY_TABLE}" not in ipv6_rule.stdout:
        raise ConnectionSessionError("The IPv6 leak-blocking rule is not active")
    ipv6_probe = runner.run(
        ("ip", "-6", "route", "get", "2606:4700:4700::1111"),
        timeout=5,
    )
    if ipv6_probe.succeeded:
        raise ConnectionSessionError("IPv6 traffic still has a usable route outside the VPN")

    try:
        public_ip_result = runner.run(
            (
                "curl",
                "-4",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "https://api.ipify.org",
            ),
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not public_ip_result.succeeded:
        return None
    try:
        address = ipaddress.IPv4Address(public_ip_result.stdout.strip())
    except ipaddress.AddressValueError:
        return None
    return str(address) if address.is_global else None


def _remove_owned_ipv4_routes(
    runner: CommandRunner,
    state: SessionState,
    errors: list[str],
) -> None:
    if state.vpn_gateway is None or state.vpn_address is None:
        return
    for prefix in IPV4_VPN_ROUTES:
        shown = runner.run(("ip", "-4", "route", "show", prefix), timeout=5)
        if not shown.succeeded:
            errors.append(f"route inspection for {prefix}: {_detail(shown)}")
            continue
        if not shown.stdout.strip():
            continue
        if not _route_matches(
            shown.stdout,
            prefix,
            state.vpn_gateway,
            state.vpn_address,
        ):
            errors.append(f"route {prefix} no longer matches project ownership")
            continue
        removed = runner.run(
            (
                "ip",
                "-4",
                "route",
                "del",
                prefix,
                "via",
                state.vpn_gateway,
                "dev",
                VPN_INTERFACE,
                "src",
                state.vpn_address,
            ),
            timeout=10,
        )
        if not removed.succeeded:
            errors.append(f"route removal for {prefix}: {_detail(removed)}")
            continue
        verified = runner.run(("ip", "-4", "route", "show", prefix), timeout=5)
        if not verified.succeeded:
            errors.append(f"route removal verification for {prefix}: {_detail(verified)}")
        elif verified.stdout.strip():
            errors.append(f"route {prefix} is still present after removal")


def _remove_ipv6_block(runner: CommandRunner, errors: list[str]) -> None:
    rule = runner.run(
        ("ip", "-6", "rule", "show", "priority", str(IPV6_RULE_PRIORITY)),
        timeout=5,
    )
    if rule.succeeded and f"lookup {IPV6_POLICY_TABLE}" in rule.stdout:
        removed_rule = runner.run(
            (
                "ip",
                "-6",
                "rule",
                "del",
                "priority",
                str(IPV6_RULE_PRIORITY),
                "lookup",
                str(IPV6_POLICY_TABLE),
            ),
            timeout=10,
        )
        if not removed_rule.succeeded:
            errors.append(f"IPv6 rule removal: {_detail(removed_rule)}")
        else:
            verified_rule = runner.run(
                (
                    "ip",
                    "-6",
                    "rule",
                    "show",
                    "priority",
                    str(IPV6_RULE_PRIORITY),
                ),
                timeout=5,
            )
            if not verified_rule.succeeded or verified_rule.stdout.strip():
                errors.append("IPv6 rule is still present after removal")
    elif not rule.succeeded:
        errors.append(f"IPv6 rule inspection: {_detail(rule)}")

    route = runner.run(
        ("ip", "-6", "route", "show", "table", "all"),
        timeout=5,
    )
    owned_route_exists = any(
        "unreachable default" in line and f"table {IPV6_POLICY_TABLE}" in line
        for line in route.stdout.splitlines()
    )
    if route.succeeded and owned_route_exists:
        removed_route = runner.run(
            (
                "ip",
                "-6",
                "route",
                "del",
                "unreachable",
                "default",
                "metric",
                str(IPV6_ROUTE_METRIC),
                "table",
                str(IPV6_POLICY_TABLE),
            ),
            timeout=10,
        )
        if not removed_route.succeeded:
            errors.append(f"IPv6 route removal: {_detail(removed_route)}")
        else:
            verified_route = runner.run(
                ("ip", "-6", "route", "show", "table", "all"),
                timeout=5,
            )
            if not verified_route.succeeded:
                errors.append(
                    f"IPv6 route removal verification: {_detail(verified_route)}"
                )
            elif any(
                "unreachable default" in line
                and f"table {IPV6_POLICY_TABLE}" in line
                for line in verified_route.stdout.splitlines()
            ):
                errors.append("IPv6 route is still present after removal")
    elif not route.succeeded:
        errors.append(f"IPv6 route inspection: {_detail(route)}")


def _cleanup_runtime_files(errors: list[str]) -> None:
    for path in (
        DEFAULT_LEASE_STATE,
        DHCLIENT_CONFIG,
        DHCLIENT_LEASE,
        DHCLIENT_PID,
        DHCLIENT_HOOK,
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            errors.append(f"runtime file cleanup for {path.name}: {error}")


def _project_dhclient_processes() -> list[psutil.Process]:
    matched: list[psutil.Process] = []
    for process in psutil.process_iter(("pid", "cmdline")):
        try:
            command = process.info.get("cmdline") or []
            if not command:
                continue
            executable = Path(command[0]).name
            if executable != "dhclient":
                continue
            if (
                VPN_INTERFACE in command
                and str(DHCLIENT_HOOK) in command
                and str(DHCLIENT_PID) in command
            ):
                matched.append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return matched


def _still_matches_project_dhclient(process: psutil.Process) -> bool:
    try:
        command = process.cmdline()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    return bool(
        command
        and Path(command[0]).name == "dhclient"
        and VPN_INTERFACE in command
        and str(DHCLIENT_HOOK) in command
        and str(DHCLIENT_PID) in command
    )


def _write_dhclient_stop_pid(pid: int) -> None:
    DHCLIENT_PID.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        DHCLIENT_PID,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, f"{pid}\n".encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _terminate_project_dhclient(
    runner: CommandRunner | None = None,
) -> int:
    runner = runner or CommandRunner()
    matched = _project_dhclient_processes()
    for process in matched:
        try:
            process.terminate()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    _, alive = psutil.wait_procs(matched, timeout=2)
    confirmed_alive: list[psutil.Process] = []
    for process in alive:
        if not _still_matches_project_dhclient(process):
            continue
        confirmed_alive.append(process)
        _write_dhclient_stop_pid(process.pid)
        runner.run(
            ("dhclient", "-x", "-pf", str(DHCLIENT_PID)),
            timeout=10,
        )
    alive = confirmed_alive
    if confirmed_alive:
        _, alive = psutil.wait_procs(confirmed_alive, timeout=2)
    for process in alive:
        try:
            process.kill()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    still_alive: list[psutil.Process] = []
    if alive:
        _, still_alive = psutil.wait_procs(alive, timeout=2)
    if still_alive:
        identifiers = ", ".join(str(process.pid) for process in still_alive)
        raise ConnectionSessionError(
            f"Project dhclient processes are still running: {identifiers}"
        )
    return len(matched)


def _cleanup_orphans_locked(
    runner: CommandRunner,
    directory: Path,
    *,
    route_store: RouteGuardStore,
) -> tuple[list[str], list[str]]:
    actions: list[str] = []
    errors: list[str] = []
    try:
        terminated = _terminate_project_dhclient(runner)
    except (OSError, ConnectionSessionError) as error:
        errors.append(f"orphan DHCP process cleanup: {error}")
        terminated = 0
    if terminated:
        flushed = runner.run(
            ("ip", "-4", "address", "flush", "dev", VPN_INTERFACE, "scope", "global"),
            timeout=10,
        )
        if flushed.succeeded:
            actions.append(f"terminated {terminated} orphan project DHCP process(es)")
        else:
            errors.append(f"orphan VPN address cleanup: {_detail(flushed)}")

    try:
        route_state = route_store.load()
        if route_state is not None:
            _unprotect_server_route_locked(runner=runner, store=route_store)
            actions.append("recovered the owned VPN server route")
    except Exception as error:
        errors.append(f"orphan VPN server route cleanup: {error}")

    tunnel = runner.run(
        _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
        timeout=10,
    )
    if tunnel.succeeded and CONNECTED_STATUS in tunnel.stdout:
        disconnected = runner.run(
            _vpncmd_args(directory, "AccountDisconnect", ACCOUNT_NAME),
            timeout=10,
        )
        if disconnected.succeeded:
            actions.append("recovered the orphan SoftEther tunnel")
        else:
            errors.append(f"orphan SoftEther disconnect: {_detail(disconnected)}")
    _cleanup_runtime_files(errors)
    return actions, errors


def _cleanup_locked(
    runner: CommandRunner,
    directory: Path,
    state: SessionState,
    *,
    route_store: RouteGuardStore,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    actions: list[str] = []
    if state.dns_owned:
        reverted = runner.run(("resolvectl", "revert", VPN_INTERFACE), timeout=10)
        if reverted.succeeded:
            actions.append("VPN DNS reverted")
        else:
            errors.append(f"DNS cleanup: {_detail(reverted)}")
    if state.ipv4_routes_owned:
        _remove_owned_ipv4_routes(runner, state, errors)
        actions.append("owned IPv4 routes removed")
    if state.ipv6_block_owned:
        _remove_ipv6_block(runner, errors)
        actions.append("owned IPv6 block removed")
    if state.dhcp_started:
        if DHCLIENT_CONFIG.exists() and DHCLIENT_HOOK.exists():
            runner.run(
                (
                    "dhclient",
                    "-4",
                    "-r",
                    "-v",
                    "-cf",
                    str(DHCLIENT_CONFIG),
                    "-lf",
                    str(DHCLIENT_LEASE),
                    "-pf",
                    str(DHCLIENT_PID),
                    "-sf",
                    str(DHCLIENT_HOOK),
                    VPN_INTERFACE,
                ),
                timeout=15,
            )
        try:
            _terminate_project_dhclient(runner)
        except (OSError, ConnectionSessionError) as error:
            errors.append(f"DHCP process cleanup: {error}")
        flushed = runner.run(
            ("ip", "-4", "address", "flush", "dev", VPN_INTERFACE, "scope", "global"),
            timeout=10,
        )
        if not flushed.succeeded:
            errors.append(f"VPN address cleanup: {_detail(flushed)}")
        actions.append("VPN DHCP lease removed")
    if state.tunnel_requested:
        disconnected = runner.run(
            _vpncmd_args(directory, "AccountDisconnect", ACCOUNT_NAME),
            timeout=10,
        )
        detail = f"{disconnected.stdout}\n{disconnected.stderr}".casefold()
        already_disconnected = "error code: 37" in detail and "not connected" in detail
        if not disconnected.succeeded and not already_disconnected:
            errors.append(f"SoftEther disconnect: {_detail(disconnected)}")
        else:
            actions.append("SoftEther tunnel disconnected")
    if state.server_route_owned:
        try:
            _unprotect_server_route_locked(runner=runner, store=route_store)
            actions.append("VPN server route removed")
        except Exception as error:
            errors.append(f"VPN server route cleanup: {error}")
    _cleanup_runtime_files(errors)
    return actions, errors


def connect_vpn(
    server_ip: str,
    *,
    project_root: Path,
    timeout_seconds: int = 30,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
    store: SessionStore | None = None,
    route_store: RouteGuardStore | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
    sleeper: Callable[[float], None] = time.sleep,
) -> ConnectionResult:
    server_ip = validate_server_ip(server_ip)
    if timeout_seconds <= 0:
        raise ValueError("Timeout must be positive")
    _require_dhclient_policy()
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise ConnectionSessionError("SoftEther VPN Client was not found")
    store = store or SessionStore()
    route_store = route_store or RouteGuardStore()

    with connection_lock(lock_path):
        previous = store.load()
        if previous is not None:
            raise ConnectionSessionError(
                "A connection state already exists; run vpngate status or "
                "sudo vpngate recover --apply"
            )
        baseline = inspect_network_baseline(server_ip, runner=runner)
        if baseline.vpn_ipv4_addresses:
            raise ConnectionSessionError(
                "vpn_vpn already has an IPv4 address; recover it before connecting"
            )
        state = _initial_state(baseline)
        store.save(state)
        try:
            if route_store.load() is not None:
                raise ConnectionSessionError(
                    "A project server-route state already exists; run recovery first"
                )
            state = state.model_copy(update={"server_route_owned": True})
            store.save(state)
            _, created = _protect_server_route_locked(
                server_ip,
                runner=runner,
                store=route_store,
            )
            if not created:
                raise ConnectionSessionError(
                    "The server route was already active before this connection"
                )
            _set_account_endpoint(runner, directory, server_ip)
            current_tunnel = runner.run(
                _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
                timeout=10,
            )
            if current_tunnel.succeeded and CONNECTED_STATUS in current_tunnel.stdout:
                raise ConnectionSessionError(
                    "The SoftEther account is already connected without session ownership"
                )
            state = state.model_copy(update={"tunnel_requested": True})
            store.save(state)
            status_checks = _connect_tunnel(
                runner,
                directory,
                timeout_seconds=timeout_seconds,
                sleeper=sleeper,
            )

            state = state.model_copy(update={"dhcp_started": True})
            store.save(state)
            lease = _acquire_persistent_lease(
                runner,
                project_root,
                timeout_seconds=timeout_seconds,
            )
            state = state.model_copy(
                update={
                    "vpn_address": lease.address,
                    "vpn_prefix_length": lease.prefix_length,
                    "vpn_gateway": lease.offered_routers[0],
                    "vpn_dns_servers": lease.offered_dns_servers,
                }
            )
            store.save(state)

            _preflight_ipv6_block(runner)
            state = state.model_copy(update={"ipv6_block_owned": True})
            store.save(state)
            _apply_ipv6_block(runner)

            _preflight_ipv4_routes(runner)
            state = state.model_copy(update={"ipv4_routes_owned": True})
            store.save(state)
            _apply_ipv4_routes(
                runner,
                gateway=lease.offered_routers[0],
                address=lease.address,
            )

            _preflight_dns(runner)
            state = state.model_copy(update={"dns_owned": True})
            store.save(state)
            _apply_dns(runner, lease.offered_dns_servers)

            public_ip = _verify_connected(runner, state)
            state = state.model_copy(
                update={"phase": "connected", "public_ip": public_ip}
            )
            store.save(state)
            return ConnectionResult(
                server_ip=server_ip,
                vpn_address=f"{lease.address}/{lease.prefix_length}",
                vpn_gateway=lease.offered_routers[0],
                vpn_dns_servers=lease.offered_dns_servers,
                status_checks=status_checks,
                public_ip=public_ip,
            )
        except BaseException as error:
            _, cleanup_errors = _cleanup_locked(
                runner,
                directory,
                state,
                route_store=route_store,
            )
            if cleanup_errors:
                store.save(state.model_copy(update={"phase": "disconnecting"}))
                raise ConnectionSessionError(
                    f"{error}; cleanup issues: {'; '.join(cleanup_errors)}"
                ) from error
            store.clear()
            if isinstance(error, ConnectionSessionError):
                raise
            if isinstance(error, (OSError, subprocess.TimeoutExpired)):
                raise ConnectionSessionError(str(error)) from error
            raise


def disconnect_vpn(
    *,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
    store: SessionStore | None = None,
    route_store: RouteGuardStore | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> DisconnectResult:
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise ConnectionSessionError("SoftEther VPN Client was not found")
    store = store or SessionStore()
    route_store = route_store or RouteGuardStore()
    with connection_lock(lock_path):
        state = store.load()
        if state is None:
            actions, errors = _cleanup_orphans_locked(
                runner,
                directory,
                route_store=route_store,
            )
            if errors:
                raise ConnectionSessionError(
                    f"Orphan recovery is incomplete: {'; '.join(errors)}"
                )
            return DisconnectResult(
                had_state=False,
                cleanup_actions=tuple(actions),
            )
        state = state.model_copy(update={"phase": "disconnecting"})
        store.save(state)
        actions, errors = _cleanup_locked(
            runner,
            directory,
            state,
            route_store=route_store,
        )
        if errors:
            raise ConnectionSessionError(
                f"Recovery is incomplete: {'; '.join(errors)}"
            )
        store.clear()
        return DisconnectResult(had_state=True, cleanup_actions=tuple(actions))


def inspect_connection_status(
    *,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
    store: SessionStore | None = None,
) -> ConnectionStatus:
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise ConnectionSessionError("SoftEther VPN Client was not found")
    store = store or SessionStore()
    state = store.load()
    tunnel = runner.run(
        _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
        timeout=10,
    )
    tunnel_connected = tunnel.succeeded and CONNECTED_STATUS in tunnel.stdout
    addresses = runner.run(
        ("ip", "-4", "-brief", "address", "show", VPN_INTERFACE),
        timeout=5,
    )
    vpn_addresses = tuple(
        token for token in addresses.stdout.split() if "." in token and "/" in token
    ) if addresses.succeeded else ()
    routes_active = all(
        runner.run(("ip", "-4", "route", "show", prefix), timeout=5).stdout.strip()
        for prefix in IPV4_VPN_ROUTES
    )
    dns = runner.run(("resolvectl", "status", VPN_INTERFACE), timeout=5)
    dns_active = dns.succeeded and "~." in dns.stdout
    ipv6 = runner.run(
        ("ip", "-6", "rule", "show", "priority", str(IPV6_RULE_PRIORITY)),
        timeout=5,
    )
    ipv6_active = ipv6.succeeded and f"lookup {IPV6_POLICY_TABLE}" in ipv6.stdout
    return ConnectionStatus(
        state=state,
        tunnel_connected=tunnel_connected,
        vpn_addresses=vpn_addresses,
        ipv4_routes_active=routes_active,
        dns_active=dns_active,
        ipv6_block_active=ipv6_active,
        project_dhclient_processes=len(_project_dhclient_processes()),
    )


def verify_connection(
    *,
    runner: CommandRunner | None = None,
    store: SessionStore | None = None,
) -> VerificationResult:
    runner = runner or CommandRunner()
    store = store or SessionStore()
    state = store.load()
    if state is None or state.phase != "connected":
        raise ConnectionSessionError("No active managed VPN connection is recorded")

    public_ip = _verify_connected(runner, state)
    dns_query = runner.run(
        (
            "resolvectl",
            "query",
            "--legend=no",
            "--type=A",
            "www.vpngate.net",
        ),
        timeout=15,
    )
    ipv6_probe = runner.run(
        ("ip", "-6", "route", "get", "2606:4700:4700::1111"),
        timeout=5,
    )
    if ipv6_probe.succeeded:
        raise ConnectionSessionError(
            "IPv6 traffic still has a usable route outside the VPN"
        )
    return VerificationResult(
        public_ipv4_route=True,
        vpn_server_route=True,
        dns_routing=True,
        dns_query_succeeded=dns_query.succeeded,
        ipv6_fail_closed=True,
        public_ip=public_ip,
    )
