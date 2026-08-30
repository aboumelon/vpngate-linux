from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import subprocess
import sys
from typing import Callable

from .server_client import refresh_from_sources
from .server_storage import CacheStore, SourceStore


@dataclass(frozen=True)
class GuiRefreshResult:
    detail: str


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _refresh_directly() -> GuiRefreshResult:
    cache_store = CacheStore()
    cache = refresh_from_sources(SourceStore().all_sources(), cache_store)
    return GuiRefreshResult(
        detail=f"Cached {len(cache.servers)} servers from {cache.source_url}"
    )


def _invoking_user_id() -> int:
    value = os.environ.get("SUDO_UID")
    try:
        user_id = int(value) if value is not None else 0
    except ValueError as error:
        raise RuntimeError("SUDO_UID is invalid; restart the TUI with sudo") from error
    if user_id <= 0:
        raise RuntimeError(
            "The invoking desktop user is unknown; restart the TUI with sudo"
        )
    try:
        pwd.getpwuid(user_id)
    except KeyError as error:
        raise RuntimeError("The invoking desktop user no longer exists") from error
    return user_id


def refresh_server_cache(
    *,
    executable: Path | None = None,
    runner: CommandRunner = subprocess.run,
) -> GuiRefreshResult:
    """Refresh as the desktop user, never as root."""

    if os.geteuid() != 0:
        return _refresh_directly()

    user_id = _invoking_user_id()
    cli_executable = (executable or Path(sys.argv[0])).resolve()
    if not cli_executable.is_file():
        raise RuntimeError(f"The vpngate executable was not found: {cli_executable}")

    completed = runner(
        (
            "sudo",
            "--user",
            f"#{user_id}",
            "--set-home",
            "--",
            str(cli_executable),
            "servers",
            "refresh",
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or "The server refresh command failed")
    return GuiRefreshResult(detail=completed.stdout.strip())
