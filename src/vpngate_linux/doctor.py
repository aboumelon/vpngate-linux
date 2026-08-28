from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from .command import CommandRunner
from .softether import find_softether_directory


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    required: bool = True


REQUIRED_COMMANDS = ("ip", "systemctl", "resolvectl", "dhclient")
OPTIONAL_COMMANDS = ("nmcli", "nft")


def _command_check(name: str, *, required: bool) -> CheckResult:
    path = shutil.which(name)
    return CheckResult(
        name=name,
        ok=path is not None,
        detail=path or "Not found",
        required=required,
    )


def _softether_check() -> CheckResult:
    directory = find_softether_directory()
    if directory is not None:
        return CheckResult("SoftEther", True, str(directory))
    return CheckResult(
        "SoftEther",
        False,
        "vpnclient and vpncmd were not found in a known location",
    )


def _resolved_check() -> CheckResult:
    resolv_conf = Path("/etc/resolv.conf")
    try:
        target = resolv_conf.resolve(strict=True)
    except OSError as error:
        return CheckResult("systemd-resolved", False, str(error))
    managed = "systemd/resolve" in str(target)
    detail = f"/etc/resolv.conf -> {target}"
    return CheckResult("systemd-resolved", managed, detail)


def _systemd_check(runner: CommandRunner) -> CheckResult:
    try:
        result = runner.run(("systemctl", "--version"), timeout=3)
    except (OSError, subprocess.TimeoutExpired) as error:
        return CheckResult("systemd", False, str(error))
    first_line = result.stdout.splitlines()[0] if result.stdout else result.stderr
    return CheckResult("systemd", result.succeeded, first_line)


def _apparmor_check() -> CheckResult:
    dhclient_profile = Path("/etc/apparmor.d/sbin.dhclient")
    project_policy = Path("/etc/apparmor.d/vpngate-linux-dhclient")
    if not dhclient_profile.exists():
        return CheckResult(
            "dhclient AppArmor policy",
            True,
            "The standard dhclient AppArmor profile is not installed",
            required=False,
        )
    if project_policy.exists():
        return CheckResult(
            "dhclient AppArmor policy",
            True,
            str(project_policy),
        )
    return CheckResult(
        "dhclient AppArmor policy",
        False,
        "Run sudo ./scripts/install-dhclient-apparmor-policy.sh",
    )


def run_checks(runner: CommandRunner | None = None) -> list[CheckResult]:
    runner = runner or CommandRunner()
    checks = [
        *(_command_check(name, required=True) for name in REQUIRED_COMMANDS),
        *(_command_check(name, required=False) for name in OPTIONAL_COMMANDS),
        _softether_check(),
        _resolved_check(),
        _systemd_check(runner),
        _apparmor_check(),
    ]
    return checks
