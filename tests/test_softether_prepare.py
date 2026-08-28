from pathlib import Path
import unittest

from vpngate_linux.command import CommandResult
from vpngate_linux.softether_prepare import (
    SoftEtherPreparationError,
    prepare_new_account,
)


DIRECTORY = Path("/opt/vpnclient")


def result(args: tuple[str, ...], returncode: int = 0, stdout: str = "") -> CommandResult:
    return CommandResult(args=args, returncode=returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(
        self,
        *,
        adapters: tuple[str, ...] = (),
        accounts: tuple[str, ...] = (),
        fail_command: str | None = None,
    ) -> None:
        self.adapters = adapters
        self.accounts = accounts
        self.fail_command = fail_command
        self.commands: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        command = args[4]
        self.commands.append(args)
        if command == self.fail_command:
            return result(args, returncode=1, stdout="simulated failure")
        if command == "NicList":
            output = "\n".join(
                f"Virtual Network Adapter Name | {name}" for name in self.adapters
            )
            return result(args, stdout=output)
        if command == "AccountList":
            output = "\n".join(
                f"VPN Connection Setting Name | {name}" for name in self.accounts
            )
            return result(args, stdout=output)
        if command == "AccountGet":
            return result(args, stdout="VPN Connection Setting Name | vpngate")
        return result(args)


class SoftEtherPreparationTests(unittest.TestCase):
    def test_creates_a_missing_adapter_and_account_without_connecting(self) -> None:
        runner = FakeRunner()

        prepared = prepare_new_account(
            "8.8.8.8",
            runner=runner,
            directory=DIRECTORY,
        )

        command_names = [args[4] for args in runner.commands]
        self.assertTrue(prepared.adapter_created)
        self.assertTrue(prepared.account_created)
        self.assertIn("NicCreate", command_names)
        self.assertIn("AccountCreate", command_names)
        self.assertNotIn("AccountConnect", command_names)

    def test_reuses_an_existing_adapter(self) -> None:
        runner = FakeRunner(adapters=("vpn",))

        prepared = prepare_new_account(
            "8.8.8.8",
            runner=runner,
            directory=DIRECTORY,
        )

        self.assertFalse(prepared.adapter_created)
        self.assertNotIn("NicCreate", [args[4] for args in runner.commands])

    def test_refuses_to_modify_an_existing_account(self) -> None:
        runner = FakeRunner(accounts=("vpngate",))

        with self.assertRaisesRegex(SoftEtherPreparationError, "not modified"):
            prepare_new_account(
                "8.8.8.8",
                runner=runner,
                directory=DIRECTORY,
            )

        self.assertEqual(
            [args[4] for args in runner.commands],
            ["NicList", "AccountList"],
        )

    def test_rolls_back_only_new_resources_after_failure(self) -> None:
        runner = FakeRunner(fail_command="AccountPasswordSet")

        with self.assertRaisesRegex(SoftEtherPreparationError, "simulated failure"):
            prepare_new_account(
                "8.8.8.8",
                runner=runner,
                directory=DIRECTORY,
            )

        command_names = [args[4] for args in runner.commands]
        self.assertEqual(command_names[-2:], ["AccountDelete", "NicDelete"])


if __name__ == "__main__":
    unittest.main()
