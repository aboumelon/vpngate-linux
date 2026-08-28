from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from .command import CommandRunner


SOFTETHER_LOCATIONS = (
    Path("/usr/local/vpnclient"),
    Path.home() / "vpn-projects" / "vpnclient",
)
SYSTEMD_UNIT_NAME = "vpngate-vpnclient.service"


@dataclass(frozen=True)
class SoftEtherInspection:
    directory: Path
    command_version: str
    daemon_reachable: bool
    daemon_detail: str
    unit_load_state: str
    unit_active_state: str


def find_softether_directory() -> Path | None:
    for directory in SOFTETHER_LOCATIONS:
        if (directory / "vpnclient").is_file() and (directory / "vpncmd").is_file():
            return directory
    return None


def _extract_version(output: str) -> str:
    match = re.search(r"^Version\s+(.+)$", output, flags=re.MULTILINE)
    return match.group(1).strip() if match else "Unknown"


def _systemd_states(output: str) -> tuple[str, str]:
    properties = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    return (
        properties.get("LoadState", "unknown"),
        properties.get("ActiveState", "unknown"),
    )


def inspect_softether(
    runner: CommandRunner | None = None,
    directory: Path | None = None,
) -> SoftEtherInspection:
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise FileNotFoundError("SoftEther VPN Client was not found")

    vpncmd = str(directory / "vpncmd")
    try:
        version_result = runner.run((vpncmd, "/?"), timeout=5)
        management_result = runner.run(
            (vpncmd, "localhost", "/CLIENT", "/CMD", "VersionGet"),
            timeout=5,
        )
        systemd_result = runner.run(
            (
                "systemctl",
                "show",
                SYSTEMD_UNIT_NAME,
                "--property=LoadState",
                "--property=ActiveState",
                "--no-pager",
            ),
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"SoftEther inspection failed: {error}") from error

    load_state, active_state = _systemd_states(systemd_result.stdout)
    daemon_detail = (
        "Local management connection succeeded"
        if management_result.succeeded
        else "Local management endpoint is unreachable; the daemon is probably stopped"
    )
    return SoftEtherInspection(
        directory=directory,
        command_version=_extract_version(version_result.stdout),
        daemon_reachable=management_result.succeeded,
        daemon_detail=daemon_detail,
        unit_load_state=load_state,
        unit_active_state=active_state,
    )
