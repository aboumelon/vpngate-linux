from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import math
import os
from pathlib import Path
import time
from typing import Callable, Iterator

from .command import CommandResult, CommandRunner
from .softether import find_softether_directory
from .softether_prepare import ACCOUNT_NAME, SoftEtherPreparationError, inspect_inventory


DEFAULT_LOCK_PATH = Path("/run/lock/vpngate-linux.lock")
CONNECTED_STATUS = "Connection Completed (Session Established)"


class TunnelTestError(RuntimeError):
    pass


@dataclass(frozen=True)
class TunnelTestResult:
    attempts: int
    status_detail: str
    disconnected: bool


def _vpncmd_args(directory: Path, command: str, *arguments: str) -> tuple[str, ...]:
    return (
        str(directory / "vpncmd"),
        "localhost",
        "/CLIENT",
        "/CMD",
        command,
        *arguments,
    )


def _result_detail(result: CommandResult) -> str:
    return result.stderr or result.stdout or f"exit status {result.returncode}"


def _is_connected(result: CommandResult) -> bool:
    return result.succeeded and CONNECTED_STATUS in result.stdout


def _is_already_disconnected(result: CommandResult) -> bool:
    detail = f"{result.stdout}\n{result.stderr}".casefold()
    return "error code: 37" in detail and "not connected" in detail


@contextmanager
def connection_lock(path: Path = DEFAULT_LOCK_PATH) -> Iterator[None]:
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        raise TunnelTestError(f"Could not open the connection lock: {error}") from error
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TunnelTestError("Another VPN operation is already running") from error
        yield
    finally:
        os.close(descriptor)


def _disconnect(
    runner: CommandRunner,
    directory: Path,
) -> CommandResult:
    return runner.run(
        _vpncmd_args(directory, "AccountDisconnect", ACCOUNT_NAME),
        timeout=10,
    )


def test_tunnel(
    *,
    timeout_seconds: float = 30,
    poll_interval: float = 1,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
    sleeper: Callable[[float], None] = time.sleep,
) -> TunnelTestResult:
    if timeout_seconds <= 0 or poll_interval <= 0:
        raise ValueError("Timeout and poll interval must be positive")
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise TunnelTestError("SoftEther VPN Client was not found")

    with connection_lock(lock_path):
        try:
            inventory = inspect_inventory(runner, directory)
        except SoftEtherPreparationError as error:
            raise TunnelTestError(str(error)) from error
        if ACCOUNT_NAME.casefold() not in (
            name.casefold() for name in inventory.accounts
        ):
            raise TunnelTestError("The vpngate account does not exist")

        connect_requested = False
        try:
            connect_requested = True
            connect_result = runner.run(
                _vpncmd_args(directory, "AccountConnect", ACCOUNT_NAME),
                timeout=10,
            )
            if not connect_result.succeeded:
                raise TunnelTestError(
                    f"Connection request failed: {_result_detail(connect_result)}"
                )

            attempts = max(1, math.ceil(timeout_seconds / poll_interval))
            last_detail = "No status response was received"
            for attempt in range(1, attempts + 1):
                status_result = runner.run(
                    _vpncmd_args(directory, "AccountStatusGet", ACCOUNT_NAME),
                    timeout=10,
                )
                last_detail = _result_detail(status_result)
                if _is_connected(status_result):
                    break
                if attempt < attempts:
                    sleeper(poll_interval)
            else:
                raise TunnelTestError(
                    f"The tunnel was not connected within {timeout_seconds:g} seconds: "
                    f"{last_detail}"
                )
        except BaseException as error:
            if connect_requested:
                try:
                    _disconnect(runner, directory)
                except BaseException:
                    pass
            raise

        disconnect_result = _disconnect(runner, directory)
        if not disconnect_result.succeeded and not _is_already_disconnected(
            disconnect_result
        ):
            raise TunnelTestError(
                f"Tunnel connected, but disconnect failed: "
                f"{_result_detail(disconnect_result)}"
            )
        return TunnelTestResult(
            attempts=attempt,
            status_detail=last_detail,
            disconnected=True,
        )


def disconnect_tunnel(
    *,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> bool:
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise TunnelTestError("SoftEther VPN Client was not found")
    with connection_lock(lock_path):
        result = _disconnect(runner, directory)
        if _is_already_disconnected(result):
            return False
        if not result.succeeded:
            raise TunnelTestError(f"Disconnect failed: {_result_detail(result)}")
        return True
