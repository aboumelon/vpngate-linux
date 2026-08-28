from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpngate_linux.command import CommandResult
from vpngate_linux.lease_test import (
    LeaseTestError,
    _parse_account_endpoint,
    _write_runtime_hook,
    run_lease_test,
)


SERVER_IP = "219.100.37.180"


class LeaseRunner:
    def __init__(self, state_path: Path, *, fail_dhcp: bool = False) -> None:
        self.state_path = state_path
        self.fail_dhcp = fail_dhcp
        self.has_address = False
        self.commands: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
        self.commands.append(args)
        succeeded = True
        output = ""
        if args[:4] == ("ip", "-4", "route", "get"):
            output = (
                f"{SERVER_IP} via 172.20.164.1 dev wlp0s20f3 "
                "src 172.20.166.250 uid 1000"
            )
        elif args == ("ip", "-4", "route", "show", "default"):
            output = "default via 172.20.164.1 dev wlp0s20f3"
        elif args == ("ip", "-4", "-brief", "address", "show", "vpn_vpn"):
            output = "vpn_vpn UNKNOWN"
            if self.has_address:
                output += " 10.211.1.20/24"
        elif args == ("resolvectl", "status"):
            output = "Link 3 (wlp0s20f3)\n Default Route: yes"
        elif "AccountGet" in args:
            output = (
                f"Destination VPN Server Host Name |{SERVER_IP}\n"
                "Destination VPN Server Port Number |443"
            )
        elif "AccountStatusGet" in args:
            output = "Session Status | Connection Completed (Session Established)"
        elif args[0] == "dhclient" and "-1" in args:
            if self.fail_dhcp:
                succeeded = False
                output = "simulated DHCP failure"
            else:
                self.has_address = True
                self.state_path.write_text(
                    '{"version":1,"interface":"vpn_vpn",'
                    '"address":"10.211.1.20","prefix_length":24,'
                    '"offered_routers":["10.211.1.1"],'
                    '"offered_dns_servers":["10.211.1.2"]}',
                    encoding="utf-8",
                )
        elif args[:5] == ("ip", "-4", "address", "flush", "dev"):
            self.has_address = False
        return CommandResult(
            args=args,
            returncode=0 if succeeded else 1,
            stdout=output,
            stderr="",
        )


class LeaseTestOrchestrationTests(unittest.TestCase):
    def run_case(self, *, fail_dhcp: bool = False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        project_root = root / "project"
        config = project_root / "packaging" / "dhcp" / "vpngate-dhclient.conf"
        config.parent.mkdir(parents=True)
        config.write_text("request subnet-mask;", encoding="utf-8")
        state_path = root / "runtime" / "dhcp-lease.json"
        state_path.parent.mkdir()
        runner = LeaseRunner(state_path, fail_dhcp=fail_dhcp)
        patches = (
            patch("vpngate_linux.lease_test.DEFAULT_LEASE_STATE", state_path),
            patch("vpngate_linux.lease_test.DHCLIENT_CONFIG", root / "runtime" / "config"),
            patch("vpngate_linux.lease_test.DHCLIENT_HOOK", root / "runtime" / "hook"),
            patch("vpngate_linux.lease_test.DHCLIENT_LEASE", root / "runtime" / "leases"),
            patch("vpngate_linux.lease_test.DHCLIENT_PID", root / "runtime" / "pid"),
            patch("vpngate_linux.lease_test.find_softether_directory", return_value=Path("/opt/vpnclient")),
            patch("vpngate_linux.lease_test.protect_server_route", return_value=(object(), True)),
            patch("vpngate_linux.lease_test.unprotect_server_route"),
        )
        return root, project_root, runner, patches

    def test_success_cleans_address_tunnel_and_route(self) -> None:
        root, project_root, runner, patches = self.run_case()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7] as unprotect,
        ):
            result = run_lease_test(
                SERVER_IP,
                timeout_seconds=10,
                runner=runner,
                project_root=project_root,
                lock_path=root / "lock",
                sleeper=lambda _: None,
            )

        names = [args[4] for args in runner.commands if len(args) > 4 and args[0].endswith("vpncmd")]
        self.assertEqual(result.address, "10.211.1.20")
        self.assertEqual(result.offered_routers, ("10.211.1.1",))
        self.assertIn("AccountConnect", names)
        self.assertEqual(names[-1], "AccountDisconnect")
        self.assertFalse(runner.has_address)
        unprotect.assert_called_once()

    def test_rejects_a_different_prepared_endpoint_and_cleans_route(self) -> None:
        root, project_root, runner, patches = self.run_case()
        original_run = runner.run

        def mismatched_run(args: tuple[str, ...], *, timeout: float = 10) -> CommandResult:
            result = original_run(args, timeout=timeout)
            if "AccountGet" in args:
                return CommandResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "Destination VPN Server Host Name |203.0.113.10\n"
                        "Destination VPN Server Port Number |443"
                    ),
                    stderr="",
                )
            return result

        runner.run = mismatched_run  # type: ignore[method-assign]
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7] as unprotect,
        ):
            with self.assertRaisesRegex(
                LeaseTestError,
                "expected 219.100.37.180:443, found 203.0.113.10:443",
            ):
                run_lease_test(
                    SERVER_IP,
                    timeout_seconds=10,
                    runner=runner,
                    project_root=project_root,
                    lock_path=root / "lock",
                    sleeper=lambda _: None,
                )

        unprotect.assert_called_once()

    def test_dhcp_failure_still_disconnects_and_unprotects(self) -> None:
        root, project_root, runner, patches = self.run_case(fail_dhcp=True)
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7] as unprotect,
        ):
            with self.assertRaisesRegex(LeaseTestError, "simulated DHCP failure"):
                run_lease_test(
                    SERVER_IP,
                    timeout_seconds=10,
                    runner=runner,
                    project_root=project_root,
                    lock_path=root / "lock",
                    sleeper=lambda _: None,
                )

        names = [args[4] for args in runner.commands if len(args) > 4 and args[0].endswith("vpncmd")]
        self.assertEqual(names[-1], "AccountDisconnect")
        unprotect.assert_called_once()

class AccountEndpointParsingTests(unittest.TestCase):
    def test_parses_current_softether_table(self) -> None:
        output = (
            "Destination VPN Server Host Name |219.100.37.180\n"
            "Destination VPN Server Port Number |443"
        )
        self.assertEqual(_parse_account_endpoint(output), (SERVER_IP, 443))

    def test_parses_legacy_combined_endpoint(self) -> None:
        output = "VPN Server Hostname | 219.100.37.180:443"
        self.assertEqual(_parse_account_endpoint(output), (SERVER_IP, 443))

    def test_rejects_incomplete_endpoint(self) -> None:
        output = "Destination VPN Server Host Name |219.100.37.180"
        self.assertIsNone(_parse_account_endpoint(output))


class RuntimeHookTests(unittest.TestCase):
    def test_keeps_the_virtual_environment_interpreter_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hook_path = Path(temporary) / "dhclient-hook"
            virtual_environment_python = Path(temporary) / ".venv" / "bin" / "python"

            with patch(
                "vpngate_linux.lease_test.sys.executable",
                str(virtual_environment_python),
            ):
                _write_runtime_hook(hook_path)

            first_line = hook_path.read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(first_line, f"#!{virtual_environment_python}")


if __name__ == "__main__":
    unittest.main()
