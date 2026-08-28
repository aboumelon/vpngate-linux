from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from vpngate_linux.command import CommandResult
from vpngate_linux.connection_session import (
    ConnectionSessionError,
    SessionState,
    SessionStore,
    _terminate_project_dhclient,
    connect_vpn,
    disconnect_vpn,
    inspect_connection_status,
    verify_connection,
)
from vpngate_linux.lease_test import DhcpLeaseState
from vpngate_linux.route_guard import RouteGuardStore


SERVER_IP = "219.100.37.180"


class SessionRunner:
    def __init__(
        self,
        *,
        fail_dns: bool = False,
        existing_split_route: bool = False,
    ) -> None:
        self.fail_dns = fail_dns
        self.fail_route_delete = False
        self.tunnel_connected = False
        self.vpn_address = False
        self.server_route = False
        self.split_routes = {"0.0.0.0/1": existing_split_route, "128.0.0.0/1": False}
        self.dns_active = False
        self.ipv6_route = False
        self.ipv6_rule = False
        self.commands: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        self.commands.append(args)
        output = ""
        returncode = 0

        if args[:4] == ("ip", "-4", "route", "get"):
            destination = args[4]
            if destination == "1.1.1.1" and self.split_routes["0.0.0.0/1"]:
                output = "1.1.1.1 via 10.244.254.254 dev vpn_vpn src 10.244.91.126"
            else:
                output = (
                    f"{destination} via 172.20.164.1 dev wlp0s20f3 "
                    "src 172.20.166.250"
                )
        elif args == ("ip", "-4", "route", "show", "default"):
            output = "default via 172.20.164.1 dev wlp0s20f3"
        elif args == ("ip", "-4", "-brief", "address", "show", "vpn_vpn"):
            output = "vpn_vpn UNKNOWN"
            if self.vpn_address:
                output += " 10.244.91.126/16"
        elif args[:5] == ("ip", "-4", "route", "show", f"{SERVER_IP}/32"):
            if self.server_route:
                output = (
                    f"{SERVER_IP} via 172.20.164.1 dev wlp0s20f3 "
                    "src 172.20.166.250"
                )
        elif args[:5] == ("ip", "-4", "route", "add", f"{SERVER_IP}/32"):
            self.server_route = True
        elif args[:5] == ("ip", "-4", "route", "del", f"{SERVER_IP}/32"):
            self.server_route = False
        elif args[:4] == ("ip", "-4", "route", "show") and args[4] in self.split_routes:
            prefix = args[4]
            if self.split_routes[prefix]:
                output = (
                    f"{prefix} via 10.244.254.254 dev vpn_vpn "
                    "src 10.244.91.126"
                )
        elif args[:4] == ("ip", "-4", "route", "add") and args[4] in self.split_routes:
            self.split_routes[args[4]] = True
        elif args[:4] == ("ip", "-4", "route", "del") and args[4] in self.split_routes:
            if self.fail_route_delete:
                returncode = 1
                output = "simulated route deletion failure"
            else:
                self.split_routes[args[4]] = False
        elif args[:5] == ("ip", "-4", "address", "flush", "dev"):
            self.vpn_address = False
        elif args[:5] == ("ip", "-6", "rule", "show", "priority"):
            if self.ipv6_rule:
                output = "50: from all lookup 51820"
        elif args[:5] == ("ip", "-6", "route", "show", "table"):
            if self.ipv6_route:
                output = "unreachable default metric 42760 table 51820"
        elif args[:5] == ("ip", "-6", "route", "add", "unreachable"):
            self.ipv6_route = True
        elif args[:5] == ("ip", "-6", "route", "del", "unreachable"):
            self.ipv6_route = False
        elif args[:4] == ("ip", "-6", "rule", "add"):
            self.ipv6_rule = True
        elif args[:4] == ("ip", "-6", "rule", "del"):
            self.ipv6_rule = False
        elif args[:5] == ("ip", "-6", "route", "get", "2606:4700:4700::1111"):
            returncode = 2
            output = "RTNETLINK answers: Network is unreachable"
        elif args[:2] == ("resolvectl", "status"):
            if len(args) == 2:
                output = "Link 3 (wlp0s20f3)\n Default Route: yes"
            elif self.dns_active:
                output = (
                    "Link 11 (vpn_vpn)\n"
                    " DNS Servers: 10.244.254.254 8.8.8.8\n"
                    " DNS Domain: ~.\n Default Route: yes"
                )
            else:
                output = "Link 11 (vpn_vpn)\n Default Route: no"
        elif args[:2] == ("resolvectl", "dns"):
            if self.fail_dns:
                returncode = 1
                output = "simulated DNS failure"
            else:
                self.dns_active = True
        elif args[:2] == ("resolvectl", "revert"):
            self.dns_active = False
        elif "AccountGet" in args:
            output = (
                f"Destination VPN Server Host Name |{SERVER_IP}\n"
                "Destination VPN Server Port Number |443"
            )
        elif "AccountStatusGet" in args:
            if self.tunnel_connected:
                output = "Session Status | Connection Completed (Session Established)"
            else:
                returncode = 37
                output = "Error code: 37\nThe specified VPN Connection Setting is not connected."
        elif "AccountConnect" in args:
            self.tunnel_connected = True
        elif "AccountDisconnect" in args:
            if self.tunnel_connected:
                self.tunnel_connected = False
            else:
                returncode = 37
                output = "Error code: 37\nThe specified VPN Connection Setting is not connected."
        elif args and args[0] == "curl":
            output = "203.0.113.25"

        return CommandResult(
            args=args,
            returncode=returncode,
            stdout=output,
            stderr="",
        )


class ConnectionSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        project_root = root / "project"
        config = project_root / "packaging" / "dhcp" / "vpngate-dhclient.conf"
        config.parent.mkdir(parents=True)
        config.write_text("request subnet-mask;", encoding="utf-8")
        self.project_root = project_root
        self.session_store = SessionStore(root / "connection.json")
        self.route_store = RouteGuardStore(root / "server-route.json")
        self.lock_path = root / "connection.lock"

    def lease(self, runner: SessionRunner) -> DhcpLeaseState:
        runner.vpn_address = True
        return DhcpLeaseState(
            version=1,
            interface="vpn_vpn",
            address="10.244.91.126",
            prefix_length=16,
            offered_routers=("10.244.254.254",),
            offered_dns_servers=("10.244.254.254", "8.8.8.8"),
        )

    def patches(self, runner: SessionRunner):
        return (
            patch("vpngate_linux.connection_session._require_dhclient_policy"),
            patch(
                "vpngate_linux.connection_session._acquire_persistent_lease",
                side_effect=lambda *args, **kwargs: self.lease(runner),
            ),
            patch("vpngate_linux.connection_session._cleanup_runtime_files"),
            patch("vpngate_linux.connection_session._terminate_project_dhclient"),
        )

    def connect(self, runner: SessionRunner):
        patches = self.patches(runner)
        with patches[0], patches[1], patches[2], patches[3]:
            return connect_vpn(
                SERVER_IP,
                project_root=self.project_root,
                runner=runner,
                directory=Path("/opt/vpnclient"),
                store=self.session_store,
                route_store=self.route_store,
                lock_path=self.lock_path,
                sleeper=lambda _: None,
            )

    def disconnect(self, runner: SessionRunner):
        patches = self.patches(runner)
        with patches[0], patches[1], patches[2], patches[3]:
            return disconnect_vpn(
                runner=runner,
                directory=Path("/opt/vpnclient"),
                store=self.session_store,
                route_store=self.route_store,
                lock_path=self.lock_path,
            )

    def test_connect_and_disconnect_are_symmetric(self) -> None:
        runner = SessionRunner()
        result = self.connect(runner)

        self.assertEqual(result.vpn_address, "10.244.91.126/16")
        self.assertEqual(self.session_store.load().phase, "connected")
        self.assertTrue(runner.tunnel_connected)
        self.assertTrue(all(runner.split_routes.values()))
        self.assertTrue(runner.dns_active)
        self.assertTrue(runner.ipv6_rule)

        disconnected = self.disconnect(runner)

        self.assertTrue(disconnected.had_state)
        self.assertIsNone(self.session_store.load())
        self.assertFalse(runner.tunnel_connected)
        self.assertFalse(any(runner.split_routes.values()))
        self.assertFalse(runner.dns_active)
        self.assertFalse(runner.ipv6_rule)
        self.assertFalse(runner.server_route)

    def test_dns_failure_rolls_back_every_owned_change(self) -> None:
        runner = SessionRunner(fail_dns=True)

        with self.assertRaisesRegex(ConnectionSessionError, "DNS configuration"):
            self.connect(runner)

        self.assertIsNone(self.session_store.load())
        self.assertFalse(runner.tunnel_connected)
        self.assertFalse(any(runner.split_routes.values()))
        self.assertFalse(runner.ipv6_rule)
        self.assertFalse(runner.server_route)

    def test_preexisting_split_route_is_never_removed(self) -> None:
        runner = SessionRunner(existing_split_route=True)

        with self.assertRaisesRegex(ConnectionSessionError, "without project ownership"):
            self.connect(runner)

        self.assertTrue(runner.split_routes["0.0.0.0/1"])
        self.assertFalse(runner.tunnel_connected)

    def test_status_reconciles_recorded_and_observed_state(self) -> None:
        runner = SessionRunner()
        self.connect(runner)

        status = inspect_connection_status(
            runner=runner,
            directory=Path("/opt/vpnclient"),
            store=self.session_store,
        )

        self.assertEqual(status.state.phase, "connected")
        self.assertTrue(status.tunnel_connected)
        self.assertTrue(status.ipv4_routes_active)
        self.assertTrue(status.dns_active)
        self.assertTrue(status.ipv6_block_active)

    def test_incomplete_disconnect_preserves_state_for_retry(self) -> None:
        runner = SessionRunner()
        self.connect(runner)
        runner.fail_route_delete = True

        with self.assertRaisesRegex(ConnectionSessionError, "Recovery is incomplete"):
            self.disconnect(runner)

        self.assertEqual(self.session_store.load().phase, "disconnecting")
        self.assertTrue(any(runner.split_routes.values()))

        runner.fail_route_delete = False
        result = self.disconnect(runner)

        self.assertTrue(result.had_state)
        self.assertIsNone(self.session_store.load())
        self.assertFalse(any(runner.split_routes.values()))

    def test_recovery_handles_crash_after_intent_before_mutation(self) -> None:
        runner = SessionRunner()
        pending = SessionState(
            phase="connecting",
            server_ip=SERVER_IP,
            original_gateway="172.20.164.1",
            original_interface="wlp0s20f3",
            original_source_ip="172.20.166.250",
            original_default_routes=(
                "default via 172.20.164.1 dev wlp0s20f3",
            ),
            original_dns_default_interfaces=("wlp0s20f3",),
            vpn_address="10.244.91.126",
            vpn_prefix_length=16,
            vpn_gateway="10.244.254.254",
            vpn_dns_servers=("10.244.254.254", "8.8.8.8"),
            server_route_owned=True,
            tunnel_requested=True,
            dhcp_started=True,
            ipv6_block_owned=True,
            ipv4_routes_owned=True,
            dns_owned=True,
            started_at=datetime.now(UTC),
        )
        self.session_store.save(pending)

        result = self.disconnect(runner)

        self.assertTrue(result.had_state)
        self.assertIsNone(self.session_store.load())
        self.assertFalse(runner.tunnel_connected)

    def test_recovery_without_state_removes_exact_orphan_processes(self) -> None:
        runner = SessionRunner()
        with (
            patch(
                "vpngate_linux.connection_session._terminate_project_dhclient",
                return_value=2,
            ),
            patch("vpngate_linux.connection_session._cleanup_runtime_files"),
        ):
            result = disconnect_vpn(
                runner=runner,
                directory=Path("/opt/vpnclient"),
                store=self.session_store,
                route_store=self.route_store,
                lock_path=self.lock_path,
            )

        self.assertFalse(result.had_state)
        self.assertIn(
            "terminated 2 orphan project DHCP process(es)",
            result.cleanup_actions,
        )

    def test_verification_checks_dns_and_ipv6_fail_closed(self) -> None:
        runner = SessionRunner()
        self.connect(runner)

        result = verify_connection(runner=runner, store=self.session_store)

        self.assertTrue(result.public_ipv4_route)
        self.assertTrue(result.dns_query_succeeded)
        self.assertTrue(result.ipv6_fail_closed)


class DhclientProcessCleanupTests(unittest.TestCase):
    def test_only_the_exact_project_dhclient_is_terminated(self) -> None:
        unrelated = Mock()
        unrelated.info = {
            "pid": 10,
            "cmdline": ["/usr/sbin/dhclient", "wlp0s20f3"],
        }
        project = Mock()
        project.info = {
            "pid": 20,
            "cmdline": [
                "/usr/sbin/dhclient",
                "-pf",
                "/run/vpngate-linux/dhclient.pid",
                "-sf",
                "/run/vpngate-linux/dhclient-address-only",
                "vpn_vpn",
            ],
        }

        with (
            patch(
                "vpngate_linux.connection_session.psutil.process_iter",
                return_value=[unrelated, project],
            ),
            patch(
                "vpngate_linux.connection_session.psutil.wait_procs",
                return_value=([project], []),
            ),
        ):
            terminated = _terminate_project_dhclient()

        self.assertEqual(terminated, 1)
        project.terminate.assert_called_once_with()
        unrelated.terminate.assert_not_called()

    def test_uses_dhclient_stop_when_direct_signals_are_confined(self) -> None:
        project = Mock()
        project.pid = 20
        project.info = {
            "pid": 20,
            "cmdline": [
                "dhclient",
                "-pf",
                "/run/vpngate-linux/dhclient.pid",
                "-sf",
                "/run/vpngate-linux/dhclient-address-only",
                "vpn_vpn",
            ],
        }
        project.cmdline.return_value = project.info["cmdline"]
        runner = Mock()
        runner.run.return_value = CommandResult(
            args=("dhclient", "-x"),
            returncode=0,
            stdout="",
            stderr="",
        )

        with (
            patch(
                "vpngate_linux.connection_session.psutil.process_iter",
                return_value=[project],
            ),
            patch(
                "vpngate_linux.connection_session.psutil.wait_procs",
                side_effect=[([], [project]), ([project], [])],
            ),
            patch("vpngate_linux.connection_session._write_dhclient_stop_pid") as write_pid,
        ):
            terminated = _terminate_project_dhclient(runner)

        self.assertEqual(terminated, 1)
        write_pid.assert_called_once_with(20)
        runner.run.assert_called_once_with(
            (
                "dhclient",
                "-x",
                "-pf",
                "/run/vpngate-linux/dhclient.pid",
            ),
            timeout=10,
        )


if __name__ == "__main__":
    unittest.main()
