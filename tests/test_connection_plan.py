import unittest

from vpngate_linux.connection_plan import (
    build_connection_plan,
    build_softether_preparation_plan,
    build_tunnel_test_plan,
    validate_server_ip,
)


class ValidateServerIpTests(unittest.TestCase):
    def test_accepts_public_ipv4(self) -> None:
        self.assertEqual(validate_server_ip("8.8.8.8"), "8.8.8.8")

    def test_rejects_private_ipv4(self) -> None:
        with self.assertRaisesRegex(ValueError, "public IPv4"):
            validate_server_ip("192.168.1.10")

    def test_rejects_ipv6(self) -> None:
        with self.assertRaisesRegex(ValueError, "public IPv4"):
            validate_server_ip("2001:4860:4860::8888")

    def test_rejects_invalid_text(self) -> None:
        with self.assertRaises(ValueError):
            validate_server_ip("not-an-ip")


class ConnectionPlanTests(unittest.TestCase):
    def test_plan_contains_no_shell_commands(self) -> None:
        plan = build_connection_plan("8.8.8.8")
        commands = [step.command for step in plan if step.command]
        self.assertTrue(commands)
        self.assertTrue(all(isinstance(command, tuple) for command in commands))

    def test_softether_preparation_is_a_dry_run_plan(self) -> None:
        plan = build_softether_preparation_plan("8.8.8.8")
        commands = [step.command for step in plan if step.command]

        self.assertTrue(all(isinstance(command, tuple) for command in commands))
        self.assertTrue(any("NicCreate" in command for command in commands))
        self.assertTrue(any("AccountCreate" in command for command in commands))
        self.assertTrue(any("AccountUsernameSet" in command for command in commands))
        self.assertFalse(any("AccountConnect" in command for command in commands))

    def test_tunnel_test_plan_always_ends_with_disconnect(self) -> None:
        commands = [
            step.command for step in build_tunnel_test_plan() if step.command
        ]

        self.assertIn("AccountConnect", commands[0])
        self.assertIn("AccountStatusGet", commands[1])
        self.assertIn("AccountDisconnect", commands[-1])


if __name__ == "__main__":
    unittest.main()
