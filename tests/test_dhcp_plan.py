from pathlib import Path
import unittest

from vpngate_linux.dhcp_plan import build_dhcp_test_plan
from vpngate_linux.network_state import NetworkBaseline


class DhcpPlanTests(unittest.TestCase):
    def test_plan_uses_the_restricted_config_and_hook(self) -> None:
        baseline = NetworkBaseline(
            server_ip="219.100.37.180",
            gateway="172.20.164.1",
            interface="wlp0s20f3",
            source_ip="172.20.166.250",
            default_routes=("default via 172.20.164.1 dev wlp0s20f3",),
            vpn_ipv4_addresses=(),
            dns_default_interfaces=("wlp0s20f3",),
        )

        plan = build_dhcp_test_plan(baseline, project_root=Path("/project"))
        commands = [step.command for step in plan if step.command]
        dhclient = next(command for command in commands if "dhclient" in command)

        self.assertIsInstance(dhclient, tuple)
        self.assertIn("/run/vpngate-linux/dhclient-address-only.conf", dhclient)
        self.assertIn("/run/vpngate-linux/dhclient-address-only", dhclient)
        self.assertIn("vpn_vpn", dhclient)
        self.assertNotIn("shell", dhclient)


if __name__ == "__main__":
    unittest.main()
