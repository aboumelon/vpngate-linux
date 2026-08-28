from pathlib import Path
import tempfile
import unittest

from vpngate_linux.command import CommandResult
from vpngate_linux.route_guard import (
    RouteGuardError,
    RouteGuardStore,
    protect_server_route,
    unprotect_server_route,
)


SERVER_IP = "219.100.37.180"
ROUTE = (
    "219.100.37.180 via 172.20.164.1 dev wlp0s20f3 "
    "src 172.20.166.250"
)


class RouteRunner:
    def __init__(self, *, route: str = "", fail_add: bool = False) -> None:
        self.route = route
        self.fail_add = fail_add
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
        elif args == ("resolvectl", "status"):
            output = "Link 3 (wlp0s20f3)\n Default Route: yes"
        elif args[:5] == ("ip", "-4", "route", "show", f"{SERVER_IP}/32"):
            output = self.route
        elif args[:5] == ("ip", "-4", "route", "add", f"{SERVER_IP}/32"):
            if self.fail_add:
                succeeded = False
                output = "simulated add failure"
            else:
                self.route = ROUTE
        elif args[:5] == ("ip", "-4", "route", "del", f"{SERVER_IP}/32"):
            self.route = ""
        else:
            raise AssertionError(f"Unexpected command: {args}")
        return CommandResult(
            args=args,
            returncode=0 if succeeded else 1,
            stdout=output,
            stderr="",
        )


class RouteGuardTests(unittest.TestCase):
    def context(self):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        return (
            directory,
            RouteGuardStore(root / "state" / "server-route.json"),
            root / "connection.lock",
        )

    def test_adds_verifies_and_records_the_owned_route(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner()

        state, created = protect_server_route(
            SERVER_IP,
            runner=runner,
            store=store,
            lock_path=lock_path,
        )

        self.assertTrue(created)
        self.assertEqual(state.status, "active")
        self.assertEqual(store.load(), state)
        self.assertIn("add", [part for command in runner.commands for part in command])

    def test_second_apply_is_idempotent(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner()
        protect_server_route(
            SERVER_IP, runner=runner, store=store, lock_path=lock_path
        )

        _, created = protect_server_route(
            SERVER_IP, runner=runner, store=store, lock_path=lock_path
        )

        self.assertFalse(created)
        add_commands = [command for command in runner.commands if "add" in command]
        self.assertEqual(len(add_commands), 1)

    def test_refuses_an_existing_unowned_route(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner(route=ROUTE)

        with self.assertRaisesRegex(RouteGuardError, "without project ownership"):
            protect_server_route(
                SERVER_IP,
                runner=runner,
                store=store,
                lock_path=lock_path,
            )

        self.assertIsNone(store.load())

    def test_failed_add_clears_pending_ownership(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner(fail_add=True)

        with self.assertRaisesRegex(RouteGuardError, "simulated add failure"):
            protect_server_route(
                SERVER_IP,
                runner=runner,
                store=store,
                lock_path=lock_path,
            )

        self.assertIsNone(store.load())

    def test_removes_only_the_matching_owned_route(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner()
        protect_server_route(
            SERVER_IP, runner=runner, store=store, lock_path=lock_path
        )

        state, removed = unprotect_server_route(
            runner=runner,
            store=store,
            lock_path=lock_path,
        )

        self.assertTrue(removed)
        self.assertEqual(state.server_ip, SERVER_IP)
        self.assertEqual(runner.route, "")
        self.assertIsNone(store.load())

    def test_refuses_to_remove_a_route_that_no_longer_matches(self) -> None:
        temporary, store, lock_path = self.context()
        self.addCleanup(temporary.cleanup)
        runner = RouteRunner()
        protect_server_route(
            SERVER_IP, runner=runner, store=store, lock_path=lock_path
        )
        runner.route = (
            f"{SERVER_IP} via 192.0.2.1 dev eno1 src 192.0.2.10"
        )

        with self.assertRaisesRegex(RouteGuardError, "does not match"):
            unprotect_server_route(
                runner=runner,
                store=store,
                lock_path=lock_path,
            )

        self.assertIsNotNone(store.load())
        self.assertNotIn("del", [part for command in runner.commands for part in command])


if __name__ == "__main__":
    unittest.main()
