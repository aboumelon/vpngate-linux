from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from vpngate_linux.gui_refresh import refresh_server_cache


class GuiRefreshTests(unittest.TestCase):
    def test_root_gui_refreshes_as_the_invoking_desktop_user(self) -> None:
        executable = Path("/tmp/vpngate-test-executable")
        completed = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="Cached 97 servers.\n",
            stderr="",
        )

        with (
            patch("vpngate_linux.gui_refresh.os.geteuid", return_value=0),
            patch.dict("os.environ", {"SUDO_UID": "1000"}, clear=True),
            patch("vpngate_linux.gui_refresh.pwd.getpwuid"),
            patch.object(Path, "is_file", return_value=True),
        ):
            runner = Mock(return_value=completed)
            result = refresh_server_cache(executable=executable, runner=runner)

        command = runner.call_args.args[0]
        self.assertEqual(
            command[:6],
            (
                "sudo",
                "--user",
                "#1000",
                "--set-home",
                "--",
                "/tmp/vpngate-test-executable",
            ),
        )
        self.assertEqual(command[-2:], ("servers", "refresh"))
        self.assertIn("Cached 97 servers", result.detail)

    def test_root_gui_refuses_to_refresh_without_an_invoking_user(self) -> None:
        with (
            patch("vpngate_linux.gui_refresh.os.geteuid", return_value=0),
            patch.dict("os.environ", {}, clear=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "restart the TUI with sudo"):
                refresh_server_cache(executable=Path("/tmp/vpngate"))

    def test_failed_child_refresh_preserves_the_error_message(self) -> None:
        completed = subprocess.CompletedProcess(
            args=(),
            returncode=6,
            stdout="",
            stderr="Every configured VPN Gate source failed.",
        )

        with (
            patch("vpngate_linux.gui_refresh.os.geteuid", return_value=0),
            patch.dict("os.environ", {"SUDO_UID": "1000"}, clear=True),
            patch("vpngate_linux.gui_refresh.pwd.getpwuid"),
            patch.object(Path, "is_file", return_value=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "Every configured"):
                refresh_server_cache(
                    executable=Path("/tmp/vpngate"),
                    runner=Mock(return_value=completed),
                )


if __name__ == "__main__":
    unittest.main()
