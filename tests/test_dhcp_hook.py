import json
from pathlib import Path
import tempfile
import unittest

from vpngate_linux.dhcp_hook import DhcpHookError, handle_event


class DhcpHookTests(unittest.TestCase):
    def test_bound_applies_only_the_address_and_records_offers(self) -> None:
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime" / "lease.json"
            handle_event(
                {
                    "interface": "vpn_vpn",
                    "reason": "BOUND",
                    "new_ip_address": "10.211.1.20",
                    "new_subnet_mask": "255.255.255.0",
                    "new_routers": "10.211.1.1 invalid",
                    "new_domain_name_servers": "10.211.1.2 10.211.1.3",
                },
                run=lambda args: commands.append(tuple(args)) or 0,
                state_path=state_path,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(
            commands,
            [
                (
                    "ip",
                    "-4",
                    "address",
                    "replace",
                    "10.211.1.20/24",
                    "broadcast",
                    "+",
                    "dev",
                    "vpn_vpn",
                )
            ],
        )
        self.assertEqual(state["offered_routers"], ["10.211.1.1"])
        self.assertEqual(
            state["offered_dns_servers"],
            ["10.211.1.2", "10.211.1.3"],
        )
        flattened = {part for command in commands for part in command}
        self.assertNotIn("route", flattened)
        self.assertNotIn("resolvectl", flattened)

    def test_release_flushes_only_global_ipv4_on_the_vpn_interface(self) -> None:
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "lease.json"
            state_path.write_text("{}", encoding="utf-8")

            handle_event(
                {"interface": "vpn_vpn", "reason": "RELEASE"},
                run=lambda args: commands.append(tuple(args)) or 0,
                state_path=state_path,
            )

            self.assertFalse(state_path.exists())
        self.assertEqual(
            commands,
            [
                (
                    "ip",
                    "-4",
                    "address",
                    "flush",
                    "dev",
                    "vpn_vpn",
                    "scope",
                    "global",
                )
            ],
        )

    def test_refuses_an_unexpected_interface(self) -> None:
        with self.assertRaisesRegex(DhcpHookError, "unexpected interface"):
            handle_event(
                {"interface": "wlp0s20f3", "reason": "PREINIT"},
                run=lambda _: 0,
            )

    def test_refuses_a_cached_timeout_lease(self) -> None:
        with self.assertRaisesRegex(DhcpHookError, "cached lease"):
            handle_event(
                {"interface": "vpn_vpn", "reason": "TIMEOUT"},
                run=lambda _: 0,
            )


if __name__ == "__main__":
    unittest.main()
