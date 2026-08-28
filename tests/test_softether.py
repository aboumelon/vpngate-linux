from pathlib import Path
import unittest

from vpngate_linux.command import CommandResult
from vpngate_linux.softether import inspect_softether


class FakeRunner:
    def __init__(self, daemon_reachable: bool = True) -> None:
        self.daemon_reachable = daemon_reachable
        self.calls: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        self.calls.append(args)
        if args[-1] == "/?":
            return CommandResult(args, 0, "Version 4.38 Build 9760   (English)", "")
        if "VersionGet" in args:
            if self.daemon_reachable:
                return CommandResult(args, 0, "Version 4.38", "")
            return CommandResult(args, 1, "", "Connection failed")
        return CommandResult(args, 0, "LoadState=loaded\nActiveState=active", "")


class SoftEtherInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path("/opt/test-vpnclient")

    def test_reports_version_daemon_and_unit_state(self) -> None:
        inspection = inspect_softether(FakeRunner(), self.directory)

        self.assertEqual(inspection.command_version, "4.38 Build 9760   (English)")
        self.assertTrue(inspection.daemon_reachable)
        self.assertEqual(inspection.unit_load_state, "loaded")
        self.assertEqual(inspection.unit_active_state, "active")

    def test_reports_unreachable_daemon(self) -> None:
        inspection = inspect_softether(FakeRunner(False), self.directory)

        self.assertFalse(inspection.daemon_reachable)
        self.assertEqual(
            inspection.daemon_detail,
            "Local management endpoint is unreachable; the daemon is probably stopped",
        )

    def test_inspection_commands_are_read_only(self) -> None:
        runner = FakeRunner()
        inspect_softether(runner, self.directory)

        flattened = " ".join(argument for call in runner.calls for argument in call)
        for mutating_command in ("start", "stop", "AccountConnect", "AccountSet"):
            self.assertNotIn(mutating_command, flattened)


if __name__ == "__main__":
    unittest.main()
