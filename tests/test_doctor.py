import unittest
from unittest.mock import patch

from vpngate_linux.command import CommandResult
from vpngate_linux.doctor import run_checks


class FakeRunner:
    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        return CommandResult(args, 0, "systemd 259", "")


class DoctorTests(unittest.TestCase):
    @patch("vpngate_linux.doctor.shutil.which")
    def test_missing_optional_command_does_not_become_required(self, which) -> None:
        which.side_effect = lambda name: None if name == "nft" else f"/usr/bin/{name}"

        checks = run_checks(FakeRunner())
        nft = next(check for check in checks if check.name == "nft")

        self.assertFalse(nft.ok)
        self.assertFalse(nft.required)

    @patch("vpngate_linux.doctor.shutil.which")
    def test_missing_required_command_is_reported(self, which) -> None:
        which.side_effect = lambda name: None if name == "ip" else f"/usr/bin/{name}"

        checks = run_checks(FakeRunner())
        ip = next(check for check in checks if check.name == "ip")

        self.assertFalse(ip.ok)
        self.assertTrue(ip.required)


if __name__ == "__main__":
    unittest.main()
