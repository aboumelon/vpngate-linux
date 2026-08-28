from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .command import CommandResult, CommandRunner
from .dhcp_hook import DEFAULT_LEASE_STATE, VPN_INTERFACE
from .dhcp_plan import (
    DHCLIENT_CONFIG,
    DHCLIENT_CONFIG_SOURCE,
    DHCLIENT_HOOK,
    DHCLIENT_LEASE,
    DHCLIENT_PID,
)
from .network_state import inspect_network_baseline
from .route_guard import RouteGuardError, protect_server_route, unprotect_server_route
from .softether import find_softether_directory
from .softether_prepare import ACCOUNT_NAME
from .softether_tunnel import (
    CONNECTED_STATUS,
    DEFAULT_LOCK_PATH,
    TunnelTestError,
    connection_lock,
)


class LeaseTestError(RuntimeError):
    pass


class DhcpLeaseState(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: int = Field(ge=1, le=1)
    interface: str
    address: str
    prefix_length: int = Field(ge=0, le=32)
    offered_routers: tuple[str, ...]
    offered_dns_servers: tuple[str, ...]


@dataclass(frozen=True)
class LeaseTestResult:
    address: str
    prefix_length: int
    offered_routers: tuple[str, ...]
    offered_dns_servers: tuple[str, ...]
    tunnel_status_checks: int
    default_route_unchanged: bool
    dns_route_unchanged: bool


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


def _parse_account_endpoint(output: str) -> tuple[str, int] | None:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if "|" not in line:
            continue
        label, value = line.split("|", maxsplit=1)
        fields[label.strip()] = value.strip()

    host = fields.get("Destination VPN Server Host Name")
    port_text = fields.get("Destination VPN Server Port Number")
    if host is not None and port_text is not None:
        try:
            return host, int(port_text)
        except ValueError:
            return None

    legacy_host = fields.get("VPN Server Hostname")
    if legacy_host is None:
        return None
    host, separator, port_text = legacy_host.rpartition(":")
    if not separator:
        return None
    port_text = port_text.split(maxsplit=1)[0]
    try:
        return host, int(port_text)
    except ValueError:
        return None


def _write_runtime_hook(path: Path) -> None:
    interpreter = Path(sys.executable)
    content = (
        f"#!{interpreter}\n"
        "from vpngate_linux.dhcp_hook import main\n"
        "raise SystemExit(main())\n"
    )
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
            os.fchmod(temporary.fileno(), 0o700)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise LeaseTestError(f"Could not create the restricted DHCP hook: {error}") from error


def _write_runtime_config(source: Path, destination: Path) -> None:
    try:
        content = source.read_text(encoding="utf-8")
    except OSError as error:
        raise LeaseTestError(f"Could not read the restricted DHCP configuration: {error}") from error

    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), 0o600)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise LeaseTestError(f"Could not stage the restricted DHCP configuration: {error}") from error


def _load_lease(path: Path) -> DhcpLeaseState:
    try:
        return DhcpLeaseState.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as error:
        raise LeaseTestError(f"A valid DHCP lease state was not produced: {error}") from error


def _terminate_recorded_dhclient(pid_path: Path) -> None:
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
    except (FileNotFoundError, OSError, ValueError):
        return
    try:
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        pid_path.unlink(missing_ok=True)
        return
    if b"dhclient" not in command_line or VPN_INTERFACE.encode() not in command_line:
        raise LeaseTestError("Refusing to terminate an unexpected process from the DHCP PID file")
    os.kill(pid, signal.SIGTERM)


def run_lease_test(
    server_ip: str,
    *,
    timeout_seconds: int = 30,
    runner: CommandRunner | None = None,
    project_root: Path,
    lock_path: Path = DEFAULT_LOCK_PATH,
    sleeper: Callable[[float], None] = time.sleep,
) -> LeaseTestResult:
    runner = runner or CommandRunner()
    directory = find_softether_directory()
    if directory is None:
        raise LeaseTestError("SoftEther VPN Client was not found")
    config_source = project_root / DHCLIENT_CONFIG_SOURCE
    if not config_source.is_file():
        raise LeaseTestError(f"DHCP configuration was not found: {config_source}")

    baseline = inspect_network_baseline(server_ip, runner=runner)
    if baseline.vpn_ipv4_addresses:
        raise LeaseTestError(
            "vpn_vpn already has an IPv4 address; it was not modified"
        )
    _, route_created = protect_server_route(
        server_ip,
        runner=runner,
        lock_path=lock_path,
    )
    tunnel_requested = False
    dhcp_started = False
    result: LeaseTestResult | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []

    try:
        with connection_lock(lock_path):
            account = runner.run(
                _vpncmd_args(directory, "AccountGet", ACCOUNT_NAME),
                timeout=10,
            )
            if not account.succeeded:
                raise LeaseTestError(f"Could not inspect the vpngate account: {_detail(account)}")
            endpoint = _parse_account_endpoint(account.stdout)
            if endpoint != (server_ip, 443):
                found = (
                    f"{endpoint[0]}:{endpoint[1]}"
                    if endpoint is not None
                    else "unrecognized output"
                )
                raise LeaseTestError(
                    "The prepared account endpoint does not match the requested server "
                    f"(expected {server_ip}:443, found {found})"
                )

            tunnel_requested = True
            connected = runner.run(
                _vpncmd_args(directory, "AccountConnect", ACCOUNT_NAME),
                timeout=10,
            )
            if not connected.succeeded:
                raise LeaseTestError(f"Tunnel request failed: {_detail(connected)}")

            status_checks = 0
            for status_checks in range(1, timeout_seconds + 1):
                status = runner.run(
                    _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
                    timeout=10,
                )
                if status.succeeded and CONNECTED_STATUS in status.stdout:
                    break
                if status_checks < timeout_seconds:
                    sleeper(1)
            else:
                raise LeaseTestError(
                    f"The tunnel was not established within {timeout_seconds} seconds"
                )

            for path in (DEFAULT_LEASE_STATE, DHCLIENT_LEASE, DHCLIENT_PID):
                path.unlink(missing_ok=True)
            _write_runtime_config(config_source, DHCLIENT_CONFIG)
            _write_runtime_hook(DHCLIENT_HOOK)
            dhcp_started = True
            acquired = runner.run(
                (
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
                    VPN_INTERFACE,
                ),
                timeout=timeout_seconds + 10,
            )
            if not acquired.succeeded:
                raise LeaseTestError(f"DHCP lease request failed: {_detail(acquired)}")
            try:
                lease = _load_lease(DEFAULT_LEASE_STATE)
            except LeaseTestError as error:
                raise LeaseTestError(
                    f"{error}; dhclient output: {_detail(acquired)}"
                ) from error
            after = inspect_network_baseline(server_ip, runner=runner)
            expected_address = f"{lease.address}/{lease.prefix_length}"
            if expected_address not in after.vpn_ipv4_addresses:
                raise LeaseTestError("The leased IPv4 address is not present on vpn_vpn")
            default_unchanged = after.default_routes == baseline.default_routes
            dns_unchanged = after.dns_default_interfaces == baseline.dns_default_interfaces
            if not default_unchanged or not dns_unchanged:
                raise LeaseTestError("The default route or DNS route changed unexpectedly")
            result = LeaseTestResult(
                address=lease.address,
                prefix_length=lease.prefix_length,
                offered_routers=lease.offered_routers,
                offered_dns_servers=lease.offered_dns_servers,
                tunnel_status_checks=status_checks,
                default_route_unchanged=default_unchanged,
                dns_route_unchanged=dns_unchanged,
            )
    except BaseException as error:
        primary_error = error
    finally:
        if dhcp_started:
            try:
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
                _terminate_recorded_dhclient(DHCLIENT_PID)
            except (OSError, LeaseTestError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"DHCP release: {error}")
        try:
            flushed = runner.run(
                ("ip", "-4", "address", "flush", "dev", VPN_INTERFACE, "scope", "global"),
                timeout=10,
            )
            if not flushed.succeeded:
                cleanup_errors.append(f"address cleanup: {_detail(flushed)}")
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup_errors.append(f"address cleanup: {error}")
        if tunnel_requested:
            try:
                disconnected = runner.run(
                    _vpncmd_args(directory, "AccountDisconnect", ACCOUNT_NAME),
                    timeout=10,
                )
                detail = f"{disconnected.stdout}\n{disconnected.stderr}".casefold()
                already_disconnected = (
                    "error code: 37" in detail and "not connected" in detail
                )
                if not disconnected.succeeded and not already_disconnected:
                    cleanup_errors.append(f"tunnel disconnect: {_detail(disconnected)}")
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"tunnel disconnect: {error}")
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
                cleanup_errors.append(f"runtime file cleanup: {error}")

    if route_created:
        try:
            unprotect_server_route(runner=runner, lock_path=lock_path)
        except (OSError, RouteGuardError, TunnelTestError) as error:
            cleanup_errors.append(f"server route cleanup: {error}")
    if primary_error is not None:
        if cleanup_errors:
            raise LeaseTestError(
                f"{primary_error}; cleanup issues: {'; '.join(cleanup_errors)}"
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise LeaseTestError(f"Lease test cleanup failed: {'; '.join(cleanup_errors)}")
    if result is None:
        raise LeaseTestError("Lease test ended without a result")
    return result
