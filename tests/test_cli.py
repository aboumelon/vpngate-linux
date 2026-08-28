import unittest

from typer.testing import CliRunner

from vpngate_linux.cli import app


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_help_exposes_the_complete_managed_workflow(self) -> None:
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0)
        for command in ("connect", "disconnect", "recover", "status", "verify", "gui"):
            self.assertIn(command, result.stdout)

    def test_connection_dry_run_contains_every_safety_layer(self) -> None:
        result = self.runner.invoke(
            app,
            ["connect", "219.100.37.180", "--dry-run"],
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("crash recovery", result.stdout)
        self.assertIn("IPv6", result.stdout)
        self.assertIn("systemd-resolved", result.stdout)
        self.assertIn("0.0.0.0/1", result.stdout)
        self.assertIn("No network settings were changed", result.stdout)


if __name__ == "__main__":
    unittest.main()
