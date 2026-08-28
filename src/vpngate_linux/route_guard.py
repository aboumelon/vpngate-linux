from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
import tempfile
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from .command import CommandResult, CommandRunner
from .network_state import NetworkBaseline, inspect_network_baseline
from .softether_tunnel import DEFAULT_LOCK_PATH, connection_lock


DEFAULT_STATE_PATH = Path("/run/vpngate-linux/server-route.json")


class RouteGuardError(RuntimeError):
    pass


class RouteGuardState(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: Literal[1] = 1
    status: Literal["pending", "active"]
    server_ip: str
    gateway: str
    interface: str
    source_ip: str
    created_at: datetime


class RouteGuardStore:
    def __init__(self, path: Path = DEFAULT_STATE_PATH) -> None:
        self.path = path

    def load(self) -> RouteGuardState | None:
        if not self.path.exists():
            return None
        try:
            return RouteGuardState.model_validate_json(
                self.path.read_text(encoding="utf-8")
            )
        except (OSError, ValidationError, ValueError) as error:
            raise RouteGuardError(f"Route guard state is invalid: {error}") from error

    def save(self, state: RouteGuardState) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
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
            try:
                temporary_path.unlink(missing_ok=True)
            except (OSError, UnboundLocalError):
                pass
            raise RouteGuardError(f"Could not save route guard state: {error}") from error

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            raise RouteGuardError(f"Could not remove route guard state: {error}") from error


def _state_from_baseline(
    baseline: NetworkBaseline,
    *,
    status: Literal["pending", "active"],
) -> RouteGuardState:
    return RouteGuardState(
        status=status,
        server_ip=baseline.server_ip,
        gateway=baseline.gateway,
        interface=baseline.interface,
        source_ip=baseline.source_ip,
        created_at=datetime.now(UTC),
    )


def _route_show_args(state: RouteGuardState) -> tuple[str, ...]:
    return ("ip", "-4", "route", "show", f"{state.server_ip}/32")


def _route_add_args(state: RouteGuardState) -> tuple[str, ...]:
    return (
        "ip",
        "-4",
        "route",
        "add",
        f"{state.server_ip}/32",
        "via",
        state.gateway,
        "dev",
        state.interface,
        "src",
        state.source_ip,
    )


def _route_delete_args(state: RouteGuardState) -> tuple[str, ...]:
    return (
        "ip",
        "-4",
        "route",
        "del",
        f"{state.server_ip}/32",
        "via",
        state.gateway,
        "dev",
        state.interface,
        "src",
        state.source_ip,
    )


def _route_matches(output: str, state: RouteGuardState) -> bool:
    first_line = next((line for line in output.splitlines() if line.strip()), "")
    tokens = first_line.split()
    if not tokens or tokens[0] not in {state.server_ip, f"{state.server_ip}/32"}:
        return False
    expected_pairs = (
        ("via", state.gateway),
        ("dev", state.interface),
        ("src", state.source_ip),
    )
    for marker, value in expected_pairs:
        try:
            if tokens[tokens.index(marker) + 1] != value:
                return False
        except (ValueError, IndexError):
            return False
    return True


def _detail(result: CommandResult) -> str:
    return result.stderr or result.stdout or f"exit status {result.returncode}"


def _protect_server_route_locked(
    server_ip: str,
    *,
    runner: CommandRunner,
    store: RouteGuardStore,
) -> tuple[RouteGuardState, bool]:
    baseline = inspect_network_baseline(server_ip, runner=runner)
    expected = _state_from_baseline(baseline, status="pending")
    previous = store.load()
    if previous is not None:
        previous_route = runner.run(_route_show_args(previous), timeout=5)
        if not previous_route.succeeded:
            raise RouteGuardError(
                f"Could not inspect the recorded server route: {_detail(previous_route)}"
            )
        if previous_route.stdout.strip():
            if previous.server_ip != expected.server_ip:
                raise RouteGuardError(
                    "A route guard for another server is already active"
                )
            if not _route_matches(previous_route.stdout, previous):
                raise RouteGuardError(
                    "The recorded server route no longer matches; it was not changed"
                )
            active = previous.model_copy(update={"status": "active"})
            store.save(active)
            return active, False
        store.clear()

    existing = runner.run(_route_show_args(expected), timeout=5)
    if not existing.succeeded:
        raise RouteGuardError(
            f"Could not inspect an existing server route: {_detail(existing)}"
        )
    if existing.stdout.strip():
        raise RouteGuardError(
            "A server route already exists without project ownership; it was not changed"
        )

    store.save(expected)
    added = runner.run(_route_add_args(expected), timeout=10)
    if not added.succeeded:
        store.clear()
        raise RouteGuardError(f"Could not add the server route: {_detail(added)}")

    verified = runner.run(_route_show_args(expected), timeout=5)
    if not verified.succeeded or not _route_matches(verified.stdout, expected):
        rollback = runner.run(_route_delete_args(expected), timeout=10)
        if rollback.succeeded:
            store.clear()
            rollback_detail = "the added route was rolled back"
        else:
            rollback_detail = "route rollback failed; ownership state was preserved"
        raise RouteGuardError(
            f"The added server route could not be verified; {rollback_detail}"
        )

    active = expected.model_copy(update={"status": "active"})
    store.save(active)
    return active, True


def protect_server_route(
    server_ip: str,
    *,
    runner: CommandRunner | None = None,
    store: RouteGuardStore | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[RouteGuardState, bool]:
    runner = runner or CommandRunner()
    store = store or RouteGuardStore()
    with connection_lock(lock_path):
        return _protect_server_route_locked(server_ip, runner=runner, store=store)


def _unprotect_server_route_locked(
    *,
    runner: CommandRunner,
    store: RouteGuardStore,
) -> tuple[RouteGuardState | None, bool]:
    state = store.load()
    if state is None:
        return None, False
    existing = runner.run(_route_show_args(state), timeout=5)
    if not existing.succeeded:
        raise RouteGuardError(
            f"Could not inspect the recorded server route: {_detail(existing)}"
        )
    if not existing.stdout.strip():
        store.clear()
        return state, False
    if not _route_matches(existing.stdout, state):
        raise RouteGuardError(
            "The current route does not match project ownership; it was not removed"
        )

    removed = runner.run(_route_delete_args(state), timeout=10)
    if not removed.succeeded:
        raise RouteGuardError(
            f"Could not remove the protected server route: {_detail(removed)}"
        )
    verified = runner.run(_route_show_args(state), timeout=5)
    if not verified.succeeded:
        raise RouteGuardError(
            f"Could not verify route removal: {_detail(verified)}"
        )
    if verified.stdout.strip():
        raise RouteGuardError(
            "The protected server route is still present; ownership state was preserved"
        )
    store.clear()
    return state, True


def unprotect_server_route(
    *,
    runner: CommandRunner | None = None,
    store: RouteGuardStore | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[RouteGuardState | None, bool]:
    runner = runner or CommandRunner()
    store = store or RouteGuardStore()
    with connection_lock(lock_path):
        return _unprotect_server_route_locked(runner=runner, store=store)
