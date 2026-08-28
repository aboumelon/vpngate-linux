from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .command import CommandResult, CommandRunner
from .connection_plan import validate_server_ip
from .softether import find_softether_directory


ACCOUNT_NAME = "vpngate"
ADAPTER_NAME = "vpn"


class SoftEtherPreparationError(RuntimeError):
    pass


@dataclass(frozen=True)
class SoftEtherInventory:
    adapters: frozenset[str]
    accounts: frozenset[str]


@dataclass(frozen=True)
class PreparationResult:
    server_ip: str
    adapter_created: bool
    account_created: bool
    account_detail: str


def _vpncmd_args(directory: Path, command: str, *arguments: str) -> tuple[str, ...]:
    return (
        str(directory / "vpncmd"),
        "localhost",
        "/CLIENT",
        "/CMD",
        command,
        *arguments,
    )


def _values_for_label(output: str, label: str) -> frozenset[str]:
    pattern = re.compile(rf"^{re.escape(label)}\s*\|\s*(.+?)\s*$", re.MULTILINE)
    return frozenset(match.group(1).strip() for match in pattern.finditer(output))


def _require_success(result: CommandResult, action: str) -> None:
    if result.succeeded:
        return
    detail = result.stderr or result.stdout or f"exit status {result.returncode}"
    raise SoftEtherPreparationError(f"{action} failed: {detail}")


def inspect_inventory(
    runner: CommandRunner,
    directory: Path,
) -> SoftEtherInventory:
    adapter_result = runner.run(_vpncmd_args(directory, "NicList"), timeout=10)
    _require_success(adapter_result, "Virtual adapter inspection")
    account_result = runner.run(_vpncmd_args(directory, "AccountList"), timeout=10)
    _require_success(account_result, "Connection account inspection")
    return SoftEtherInventory(
        adapters=_values_for_label(
            adapter_result.stdout,
            "Virtual Network Adapter Name",
        ),
        accounts=_values_for_label(
            account_result.stdout,
            "VPN Connection Setting Name",
        ),
    )


def prepare_new_account(
    server_ip: str,
    *,
    runner: CommandRunner | None = None,
    directory: Path | None = None,
) -> PreparationResult:
    server_ip = validate_server_ip(server_ip)
    runner = runner or CommandRunner()
    directory = directory or find_softether_directory()
    if directory is None:
        raise SoftEtherPreparationError("SoftEther VPN Client was not found")

    inventory = inspect_inventory(runner, directory)
    if ACCOUNT_NAME.casefold() in (name.casefold() for name in inventory.accounts):
        raise SoftEtherPreparationError(
            "The vpngate account already exists; it was not modified"
        )

    adapter_created = False
    account_created = False
    try:
        if ADAPTER_NAME.casefold() not in (
            name.casefold() for name in inventory.adapters
        ):
            result = runner.run(
                _vpncmd_args(directory, "NicCreate", ADAPTER_NAME),
                timeout=15,
            )
            _require_success(result, "Virtual adapter creation")
            adapter_created = True

        result = runner.run(
            _vpncmd_args(
                directory,
                "AccountCreate",
                ACCOUNT_NAME,
                f"/SERVER:{server_ip}:443",
                "/HUB:VPNGATE",
                "/USERNAME:vpn",
                f"/NICNAME:{ADAPTER_NAME}",
            ),
            timeout=15,
        )
        _require_success(result, "Connection account creation")
        account_created = True

        operations = (
            ("AccountUsernameSet", ACCOUNT_NAME, "/USERNAME:vpn"),
            (
                "AccountPasswordSet",
                ACCOUNT_NAME,
                "/PASSWORD:vpn",
                "/TYPE:standard",
            ),
            ("AccountNicSet", ACCOUNT_NAME, f"/NICNAME:{ADAPTER_NAME}"),
        )
        for command, *arguments in operations:
            result = runner.run(
                _vpncmd_args(directory, command, *arguments),
                timeout=15,
            )
            _require_success(result, command)

        account_result = runner.run(
            _vpncmd_args(directory, "AccountGet", ACCOUNT_NAME),
            timeout=10,
        )
        _require_success(account_result, "Prepared account inspection")
        return PreparationResult(
            server_ip=server_ip,
            adapter_created=adapter_created,
            account_created=account_created,
            account_detail=account_result.stdout,
        )
    except SoftEtherPreparationError as error:
        rollback_failures = []
        if account_created:
            result = runner.run(
                _vpncmd_args(directory, "AccountDelete", ACCOUNT_NAME),
                timeout=10,
            )
            if not result.succeeded:
                rollback_failures.append("account deletion")
        if adapter_created:
            result = runner.run(
                _vpncmd_args(directory, "NicDelete", ADAPTER_NAME),
                timeout=10,
            )
            if not result.succeeded:
                rollback_failures.append("adapter deletion")
        if rollback_failures:
            detail = ", ".join(rollback_failures)
            raise SoftEtherPreparationError(
                f"{error}; rollback also failed for: {detail}"
            ) from error
        raise
