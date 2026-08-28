import unittest

from vpngate_linux.command import CommandResult
from vpngate_linux.network_state import (
    build_server_route_guard_plan,
    inspect_network_baseline,
    parse_brief_ipv4,
    parse_dns_default_interfaces,
    parse_route_get,
)


class NetworkRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        self.commands.append(args)
        if args[:4] == ("ip", "-4", "route", "get"):
            output = (
                "219.100.37.180 via 172.20.164.1 dev wlp0s20f3 "
                "src 172.20.166.250 uid 1000"
            )
        elif args == ("ip", "-4", "route", "show", "default"):
            output = (
                "default via 172.20.164.1 dev wlp0s20f3 "
                "proto dhcp src 172.20.166.250 metric 600"
            )
        elif args == ("ip", "-4", "-brief", "address", "show", "vpn_vpn"):
            output = "vpn_vpn UNKNOWN 10.211.1.20/24"
        elif args == ("resolvectl", "status"):
            output = (
                "Link 3 (wlp0s20f3)\n"
                "    Current Scopes: DNS\n"
                "    Default Route: yes\n"
                "Link 11 (vpn_vpn)\n"
                "    Default Route: no"
            )
        else:
            raise AssertionError(f"Unexpected command: {args}")
        return CommandResult(args=args, returncode=0, stdout=output, stderr="")


class NetworkParsingTests(unittest.TestCase):
    def test_parses_route_get_fields(self) -> None:
        parsed = parse_route_get(
            "8.8.8.8 via 172.20.164.1 dev wlp0s20f3 src 172.20.166.250"
        )

        self.assertEqual(parsed, ("172.20.164.1", "wlp0s20f3", "172.20.166.250"))

    def test_parses_interface_addresses(self) -> None:
        addresses = parse_brief_ipv4("vpn_vpn UNKNOWN 10.211.1.20/24")

        self.assertEqual(addresses, ("10.211.1.20/24",))

    def test_parses_only_default_dns_interfaces(self) -> None:
        interfaces = parse_dns_default_interfaces(
            "Link 3 (wlp0s20f3)\n Default Route: yes\n"
            "Link 11 (vpn_vpn)\n Default Route: no"
        )

        self.assertEqual(interfaces, ("wlp0s20f3",))


class NetworkBaselineTests(unittest.TestCase):
    def test_inspects_the_baseline_with_read_only_commands(self) -> None:
        runner = NetworkRunner()

        baseline = inspect_network_baseline("219.100.37.180", runner=runner)

        self.assertEqual(baseline.gateway, "172.20.164.1")
        self.assertEqual(baseline.interface, "wlp0s20f3")
        self.assertEqual(baseline.source_ip, "172.20.166.250")
        self.assertEqual(baseline.vpn_ipv4_addresses, ("10.211.1.20/24",))
        self.assertEqual(baseline.dns_default_interfaces, ("wlp0s20f3",))
        self.assertTrue(all(command[0] in {"ip", "resolvectl"} for command in runner.commands))

    def test_route_guard_is_a_single_host_route_without_a_shell(self) -> None:
        baseline = inspect_network_baseline("219.100.37.180", runner=NetworkRunner())

        commands = [
            step.command
            for step in build_server_route_guard_plan(baseline)
            if step.command
        ]

        self.assertEqual(len(commands), 1)
        self.assertIsInstance(commands[0], tuple)
        self.assertIn("219.100.37.180/32", commands[0])
        self.assertIn("172.20.164.1", commands[0])
        self.assertNotIn("0.0.0.0/0", commands[0])


if __name__ == "__main__":
    unittest.main()
