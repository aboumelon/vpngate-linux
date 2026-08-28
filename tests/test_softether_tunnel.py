from pathlib import Path
import tempfile
import unittest

from vpngate_linux.command import CommandResult
from vpngate_linux.softether_tunnel import (
    TunnelTestError,
    disconnect_tunnel,
    test_tunnel,
)


DIRECTORY = Path("/opt/vpnclient")


def command_result(
    args: tuple[str, ...],
    *,
    succeeded: bool = True,
    detail: str = "",
) -> CommandResult:
    return CommandResult(
        args=args,
        returncode=0 if succeeded else 1,
        stdout=detail,
        stderr="",
    )


class TunnelRunner:
    def __init__(
        self,
        *,
        status_failures: int = 0,
        fail_connect: bool = False,
        fail_disconnect: bool = False,
        account_exists: bool = True,
    ) -> None:
        self.status_failures = status_failures
        self.fail_connect = fail_connect
        self.fail_disconnect = fail_disconnect
        self.account_exists = account_exists
        self.commands: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        self.commands.append(args)
        command = args[4]
        if command == "NicList":
            return command_result(args, detail="Virtual Network Adapter Name | vpn")
        if command == "AccountList":
            detail = "VPN Connection Setting Name | vpngate" if self.account_exists else ""
            return command_result(args, detail=detail)
        if command == "AccountConnect" and self.fail_connect:
            return command_result(args, succeeded=False, detail="connect failed")
        if command == "AccountStatusGet":
            if self.status_failures > 0:
                self.status_failures -= 1
                return command_result(args, succeeded=False, detail="not connected")
            return command_result(
                args,
                detail=(
                    "Session Status | "
                    "Connection Completed (Session Established)"
                ),
            )
        if command == "AccountDisconnect" and self.fail_disconnect:
            return command_result(args, succeeded=False, detail="disconnect failed")
        return command_result(args)


class TunnelTestTests(unittest.TestCase):
    def run_test(self, runner: TunnelRunner, *, timeout: float = 3):
        with tempfile.TemporaryDirectory() as directory:
            return test_tunnel(
                timeout_seconds=timeout,
                poll_interval=1,
                runner=runner,
                directory=DIRECTORY,
                lock_path=Path(directory) / "connection.lock",
                sleeper=lambda _: None,
            )

    def test_connects_polls_and_always_disconnects(self) -> None:
        runner = TunnelRunner(status_failures=1)

        result = self.run_test(runner)

        commands = [args[4] for args in runner.commands]
        self.assertEqual(result.attempts, 2)
        self.assertTrue(result.disconnected)
        self.assertEqual(commands[-1], "AccountDisconnect")
        self.assertNotIn("dhclient", commands)
        self.assertNotIn("ip", commands)
        self.assertNotIn("resolvectl", commands)

    def test_timeout_still_disconnects(self) -> None:
        runner = TunnelRunner(status_failures=10)

        with self.assertRaisesRegex(TunnelTestError, "not connected within"):
            self.run_test(runner, timeout=2)

        self.assertEqual(runner.commands[-1][4], "AccountDisconnect")

    def test_failed_connect_request_still_attempts_disconnect(self) -> None:
        runner = TunnelRunner(fail_connect=True)

        with self.assertRaisesRegex(TunnelTestError, "Connection request failed"):
            self.run_test(runner)

        self.assertEqual(runner.commands[-1][4], "AccountDisconnect")

    def test_refuses_to_connect_without_the_account(self) -> None:
        runner = TunnelRunner(account_exists=False)

        with self.assertRaisesRegex(TunnelTestError, "does not exist"):
            self.run_test(runner)

        self.assertNotIn("AccountConnect", [args[4] for args in runner.commands])

    def test_reports_disconnect_failure_after_success(self) -> None:
        runner = TunnelRunner(fail_disconnect=True)

        with self.assertRaisesRegex(TunnelTestError, "disconnect failed"):
            self.run_test(runner)

    def test_recovery_treats_error_37_as_already_disconnected(self) -> None:
        class DisconnectedRunner(TunnelRunner):
            def run(self, args, *, timeout=10):
                if args[4] == "AccountDisconnect":
                    self.commands.append(args)
                    return command_result(
                        args,
                        succeeded=False,
                        detail=(
                            "Error occurred. (Error code: 37)\n"
                            "The specified VPN Connection Setting is not connected."
                        ),
                    )
                return super().run(args, timeout=timeout)

        runner = DisconnectedRunner()
        with tempfile.TemporaryDirectory() as directory:
            disconnected = disconnect_tunnel(
                runner=runner,
                directory=DIRECTORY,
                lock_path=Path(directory) / "connection.lock",
            )

        self.assertFalse(disconnected)


if __name__ == "__main__":
    unittest.main()
