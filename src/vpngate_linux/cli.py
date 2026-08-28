from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
import os
from pathlib import Path
import subprocess

import typer
from rich.console import Console
from rich.table import Table

from .command import CommandRunner
from .connection_session import (
    ConnectionSessionError,
    connect_vpn,
    disconnect_vpn,
    inspect_connection_status,
    verify_connection,
)
from .connection_plan import (
    build_connection_plan,
    build_softether_preparation_plan,
    build_tunnel_test_plan,
)
from .doctor import run_checks
from .dhcp_plan import build_dhcp_test_plan
from .lease_test import LeaseTestError, run_lease_test
from .network_state import (
    NetworkInspectionError,
    build_server_route_guard_plan,
    inspect_network_baseline,
)
from .route_guard import (
    RouteGuardError,
    RouteGuardStore,
    protect_server_route,
    unprotect_server_route,
)
from .server_client import AllSourcesFailed, import_server_file, refresh_from_sources
from .server_storage import (
    CacheStore,
    SourceStore,
    normalize_source_url,
    require_http_opt_in,
)
from .server_selection import SelectionCriteria, select_servers
from .softether import find_softether_directory, inspect_softether
from .softether_prepare import (
    SoftEtherPreparationError,
    inspect_inventory,
    prepare_new_account,
)
from .softether_tunnel import TunnelTestError, disconnect_tunnel, test_tunnel


app = typer.Typer(
    name="vpngate",
    help="A safe, educational VPN Gate client for Linux",
    no_args_is_help=True,
)
console = Console()
softether_app = typer.Typer(help="Inspect and manage the local SoftEther client")
app.add_typer(softether_app, name="softether")
servers_app = typer.Typer(help="Refresh and inspect the VPN Gate server cache")
app.add_typer(servers_app, name="servers")
sources_app = typer.Typer(help="Manage VPN Gate API and mirror sources")
app.add_typer(sources_app, name="sources")
network_app = typer.Typer(help="Inspect and protect the original network path")
app.add_typer(network_app, name="network")


class ExitCode(int, Enum):
    OK = 0
    CHECK_FAILED = 1
    INVALID_INPUT = 2
    NOT_IMPLEMENTED = 3
    INSPECTION_FAILED = 4
    DATA_ERROR = 5
    NETWORK_ERROR = 6


@app.command()
def doctor() -> None:
    """Check system prerequisites without making changes."""

    results = run_checks()
    table = Table(title="vpngate environment check")
    table.add_column("Status", justify="center")
    table.add_column("Component")
    table.add_column("Details")
    for result in results:
        if result.ok:
            marker = "[green]✓[/green]"
        elif result.required:
            marker = "[red]✗[/red]"
        else:
            marker = "[yellow]![/yellow]"
        table.add_row(marker, result.name, result.detail)
    console.print(table)

    failed = [item for item in results if item.required and not item.ok]
    if failed:
        console.print("[red]One or more required components are unavailable.[/red]")
        raise typer.Exit(ExitCode.CHECK_FAILED)
    console.print("[green]The base system requirements are ready.[/green]")


@app.command()
def connect(
    server_ip: str = typer.Argument(help="Public IPv4 address of a VPN Gate server"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the planned steps without changing the system",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Establish the VPN and apply owned routes, DNS, and leak protection",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        min=10,
        max=120,
        help="Maximum tunnel and DHCP wait time in seconds",
    ),
) -> None:
    """Plan or establish a fully managed VPN connection."""

    try:
        steps = build_connection_plan(server_ip)
    except ValueError as error:
        console.print(f"[red]Invalid input:[/red] {error}")
        raise typer.Exit(ExitCode.INVALID_INPUT) from error

    if dry_run and apply:
        console.print("[red]Choose either --dry-run or --apply, not both.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)

    if apply:
        if os.geteuid() != 0:
            console.print(
                "[red]Connection requires root privileges.[/red] Run the installed "
                "virtual-environment command with sudo."
            )
            raise typer.Exit(ExitCode.CHECK_FAILED)
        try:
            result = connect_vpn(
                server_ip,
                project_root=Path(__file__).resolve().parents[2],
                timeout_seconds=timeout,
            )
        except (
            ConnectionSessionError,
            NetworkInspectionError,
            OSError,
            RouteGuardError,
            subprocess.TimeoutExpired,
            TunnelTestError,
            ValueError,
        ) as error:
            console.print(f"[red]Connection failed:[/red] {error}")
            raise typer.Exit(ExitCode.NETWORK_ERROR) from error
        console.print("[green]The VPN connection is active.[/green]")
        console.print(f"VPN server: {result.server_ip}")
        console.print(f"VPN address: {result.vpn_address}")
        console.print(f"VPN gateway: {result.vpn_gateway}")
        console.print(f"VPN DNS: {', '.join(result.vpn_dns_servers)}")
        console.print("IPv4 routing: active through vpn_vpn")
        console.print("IPv6 leak policy: blocked while connected")
        console.print(
            f"Public IPv4: {result.public_ip or 'verification endpoint unavailable'}"
        )
        console.print("Use: sudo .venv/bin/vpngate disconnect --apply")
        return

    if not dry_run:
        console.print("[yellow]Choose --dry-run or --apply.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)

    console.print(f"[bold]Connection dry-run for {server_ip}[/bold]")
    for number, step in enumerate(steps, start=1):
        console.print(f"{number}. {step.description}")
        if command := step.rendered_command():
            console.print(f"   [dim]{command}[/dim]")
    console.print("[green]Dry-run completed. No network settings were changed.[/green]")


def _require_root(action: str) -> None:
    if os.geteuid() != 0:
        console.print(
            f"[red]{action} requires root privileges.[/red] Run the installed "
            "virtual-environment command with sudo."
        )
        raise typer.Exit(ExitCode.CHECK_FAILED)


@app.command()
def disconnect(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Remove the managed VPN connection and restore the original path",
    ),
) -> None:
    """Safely disconnect and remove only project-owned network state."""

    if not apply:
        console.print("[yellow]Pass --apply to disconnect the managed VPN.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    _require_root("Disconnection")
    try:
        result = disconnect_vpn()
    except (ConnectionSessionError, OSError, subprocess.TimeoutExpired) as error:
        console.print(f"[red]Disconnection failed:[/red] {error}")
        raise typer.Exit(ExitCode.NETWORK_ERROR) from error
    if not result.had_state and not result.cleanup_actions:
        console.print("[green]No managed VPN connection was recorded.[/green]")
        return
    if result.had_state:
        console.print("[green]The managed VPN connection was removed safely.[/green]")
    else:
        console.print("[green]Orphan project state was removed safely.[/green]")
    for action in result.cleanup_actions:
        console.print(f"- {action}")


@app.command()
def recover(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Recover an interrupted connection transaction",
    ),
) -> None:
    """Clean up a connection left by an interrupted or failed process."""

    if not apply:
        console.print("[yellow]Pass --apply to run recovery.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    _require_root("Recovery")
    try:
        result = disconnect_vpn()
    except (ConnectionSessionError, OSError, subprocess.TimeoutExpired) as error:
        console.print(f"[red]Recovery failed:[/red] {error}")
        raise typer.Exit(ExitCode.NETWORK_ERROR) from error
    if not result.had_state and not result.cleanup_actions:
        console.print("[green]No interrupted connection state was found.[/green]")
        return
    console.print("[green]Recovery completed and owned state was removed.[/green]")
    for action in result.cleanup_actions:
        console.print(f"- {action}")


@app.command()
def status() -> None:
    """Inspect the managed connection and its safety controls."""

    _require_root("Status inspection")
    try:
        current = inspect_connection_status()
    except (ConnectionSessionError, OSError, subprocess.TimeoutExpired) as error:
        console.print(f"[red]Status inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    table = Table(title="Managed VPN connection status")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row(
        "Recorded phase",
        current.state.phase if current.state is not None else "not recorded",
    )
    table.add_row(
        "VPN server",
        current.state.server_ip if current.state is not None else "None",
    )
    table.add_row("SoftEther tunnel", "connected" if current.tunnel_connected else "disconnected")
    table.add_row("VPN IPv4", ", ".join(current.vpn_addresses) or "None")
    table.add_row("Owned IPv4 routes", "active" if current.ipv4_routes_active else "inactive")
    table.add_row("VPN DNS routing", "active" if current.dns_active else "inactive")
    table.add_row("IPv6 leak block", "active" if current.ipv6_block_active else "inactive")
    table.add_row("Project DHCP processes", str(current.project_dhclient_processes))
    console.print(table)


@app.command()
def verify() -> None:
    """Verify routing, DNS, public IPv4, and the IPv6 fail-closed policy."""

    _require_root("Connection verification")
    try:
        result = verify_connection()
    except (ConnectionSessionError, OSError, subprocess.TimeoutExpired) as error:
        console.print(f"[red]Verification failed:[/red] {error}")
        raise typer.Exit(ExitCode.NETWORK_ERROR) from error
    table = Table(title="Managed VPN verification")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Public IPv4 route", "vpn_vpn")
    table.add_row("VPN server route", "original interface")
    table.add_row("DNS routing", "vpn_vpn")
    table.add_row(
        "Live DNS query",
        "succeeded" if result.dns_query_succeeded else "unavailable",
    )
    table.add_row("IPv6 policy", "fail-closed")
    table.add_row("Public IPv4", result.public_ip or "endpoint unavailable")
    console.print(table)


@app.command("gui")
def gui() -> None:
    """Open the beginner-friendly terminal user interface."""

    from .tui import run_tui

    run_tui()


@softether_app.command("inspect")
def softether_inspect() -> None:
    """Inspect the local installation, daemon, and systemd unit without changes."""

    try:
        inspection = inspect_softether()
    except (FileNotFoundError, RuntimeError) as error:
        console.print(f"[red]Inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    table = Table(title="SoftEther inspection")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("Installation", str(inspection.directory))
    table.add_row("vpncmd version", inspection.command_version)
    table.add_row(
        "Daemon management",
        "reachable" if inspection.daemon_reachable else "unreachable",
    )
    table.add_row("Daemon detail", inspection.daemon_detail)
    table.add_row("systemd unit load state", inspection.unit_load_state)
    table.add_row("systemd unit active state", inspection.unit_active_state)
    console.print(table)
    console.print("[green]Inspection completed. No system state was changed.[/green]")


@softether_app.command("prepare")
def softether_prepare(
    server_ip: str = typer.Argument(help="Public IPv4 address of a VPN Gate server"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show account preparation commands without running them",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Create a new adapter and account without connecting",
    ),
) -> None:
    """Show how the SoftEther adapter and account would be prepared."""

    try:
        steps = build_softether_preparation_plan(server_ip)
    except ValueError as error:
        console.print(f"[red]Invalid input:[/red] {error}")
        raise typer.Exit(ExitCode.INVALID_INPUT) from error

    if dry_run and apply:
        console.print("[red]Choose either --dry-run or --apply, not both.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)

    if apply:
        if os.geteuid() != 0:
            console.print(
                "[red]Preparation requires root privileges.[/red] Run the installed "
                "virtual-environment command with sudo."
            )
            raise typer.Exit(ExitCode.CHECK_FAILED)
        try:
            result = prepare_new_account(server_ip)
        except SoftEtherPreparationError as error:
            console.print(f"[red]Preparation failed:[/red] {error}")
            raise typer.Exit(ExitCode.INSPECTION_FAILED) from error
        adapter_status = "created" if result.adapter_created else "already present"
        console.print("[green]SoftEther preparation completed.[/green]")
        console.print(f"Virtual adapter: {adapter_status}")
        console.print("Connection account: created")
        console.print(f"Server endpoint: {result.server_ip}:443")
        console.print("[green]No VPN connection or network change was requested.[/green]")
        return

    if not dry_run:
        console.print("[yellow]Choose --dry-run or --apply.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)

    console.print(f"[bold]SoftEther preparation dry-run for {server_ip}[/bold]")
    for number, step in enumerate(steps, start=1):
        console.print(f"{number}. {step.description}")
        if command := step.rendered_command():
            console.print(f"   [dim]{command}[/dim]")
    console.print(
        "[green]Dry-run completed. SoftEther and network settings were unchanged.[/green]"
    )


@softether_app.command("inventory")
def softether_inventory() -> None:
    """List SoftEther virtual adapters and accounts without changing them."""

    if os.geteuid() != 0:
        console.print(
            "[red]Inventory inspection requires root privileges.[/red] Run the "
            "installed virtual-environment command with sudo."
        )
        raise typer.Exit(ExitCode.CHECK_FAILED)
    directory = find_softether_directory()
    if directory is None:
        console.print("[red]SoftEther VPN Client was not found.[/red]")
        raise typer.Exit(ExitCode.INSPECTION_FAILED)
    try:
        inventory = inspect_inventory(CommandRunner(), directory)
    except SoftEtherPreparationError as error:
        console.print(f"[red]Inventory inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    table = Table(title="SoftEther configuration inventory")
    table.add_column("Type")
    table.add_column("Name")
    for adapter in sorted(inventory.adapters):
        table.add_row("Virtual adapter", adapter)
    for account in sorted(inventory.accounts):
        table.add_row("Connection account", account)
    if not inventory.adapters and not inventory.accounts:
        table.add_row("Configuration", "No adapters or accounts")
    console.print(table)
    console.print("[green]Inspection completed. No settings were changed.[/green]")


@softether_app.command("tunnel-test")
def softether_tunnel_test(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the temporary tunnel test without running it",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Connect, verify, and automatically disconnect the test tunnel",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        min=5,
        max=120,
        help="Maximum seconds to wait for an established tunnel",
    ),
) -> None:
    """Temporarily test the SoftEther tunnel without configuring IP or routes."""

    if dry_run and apply:
        console.print("[red]Choose either --dry-run or --apply, not both.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)
    if dry_run:
        console.print("[bold]Temporary SoftEther tunnel test dry-run[/bold]")
        for number, step in enumerate(build_tunnel_test_plan(), start=1):
            console.print(f"{number}. {step.description}")
            if command := step.rendered_command():
                console.print(f"   [dim]{command}[/dim]")
        console.print(
            "[green]Dry-run completed. SoftEther and network settings were unchanged.[/green]"
        )
        return
    if not apply:
        console.print("[yellow]Choose --dry-run or --apply.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    if os.geteuid() != 0:
        console.print(
            "[red]The tunnel test requires root privileges.[/red] Run the installed "
            "virtual-environment command with sudo."
        )
        raise typer.Exit(ExitCode.CHECK_FAILED)
    try:
        result = test_tunnel(timeout_seconds=timeout)
    except (OSError, TunnelTestError) as error:
        console.print(f"[red]Tunnel test failed:[/red] {error}")
        raise typer.Exit(ExitCode.NETWORK_ERROR) from error
    console.print("[green]The SoftEther tunnel was established successfully.[/green]")
    console.print(f"Status checks: {result.attempts}")
    console.print("[green]The test tunnel was disconnected automatically.[/green]")
    console.print("No DHCP, route, or DNS command was executed.")


@softether_app.command("tunnel-disconnect")
def softether_tunnel_disconnect(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Explicitly request disconnection of the vpngate account",
    ),
) -> None:
    """Provide an explicit recovery command for a lingering test tunnel."""

    if not apply:
        console.print("[yellow]Pass --apply to request disconnection.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    if os.geteuid() != 0:
        console.print(
            "[red]Disconnection requires root privileges.[/red] Run the installed "
            "virtual-environment command with sudo."
        )
        raise typer.Exit(ExitCode.CHECK_FAILED)
    try:
        disconnected = disconnect_tunnel()
    except (OSError, TunnelTestError) as error:
        console.print(f"[red]Disconnection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error
    if disconnected:
        console.print("[green]The vpngate account was disconnected.[/green]")
    else:
        console.print("[green]The vpngate account was already disconnected.[/green]")


@network_app.command("inspect")
def network_inspect(
    server_ip: str = typer.Argument(help="Public IPv4 address of the VPN server"),
) -> None:
    """Inspect the route and DNS baseline without changing the network."""

    try:
        baseline = inspect_network_baseline(server_ip)
    except (NetworkInspectionError, ValueError) as error:
        console.print(f"[red]Network inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    table = Table(title="Original network baseline")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("VPN server", baseline.server_ip)
    table.add_row("Original gateway", baseline.gateway)
    table.add_row("Original interface", baseline.interface)
    table.add_row("Original source IP", baseline.source_ip)
    table.add_row(
        "Default route",
        "\n".join(baseline.default_routes) or "None",
    )
    table.add_row(
        "VPN interface IPv4",
        ", ".join(baseline.vpn_ipv4_addresses) or "None",
    )
    table.add_row(
        "Default DNS interface",
        ", ".join(baseline.dns_default_interfaces) or "None",
    )
    console.print(table)
    console.print("[green]Inspection completed. No network settings were changed.[/green]")


@network_app.command("protect-server")
def network_protect_server(
    server_ip: str = typer.Argument(help="Public IPv4 address of the VPN server"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the dedicated server route without adding it",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Add and record ownership of the dedicated server route",
    ),
) -> None:
    """Protect the VPN server path from future default-route changes."""

    if dry_run and apply:
        console.print("[red]Choose either --dry-run or --apply, not both.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)
    if apply:
        if os.geteuid() != 0:
            console.print(
                "[red]Route protection requires root privileges.[/red] Run the "
                "installed virtual-environment command with sudo."
            )
            raise typer.Exit(ExitCode.CHECK_FAILED)
        try:
            state, created = protect_server_route(server_ip)
        except (NetworkInspectionError, OSError, RouteGuardError, ValueError) as error:
            console.print(f"[red]Route protection failed:[/red] {error}")
            raise typer.Exit(ExitCode.INSPECTION_FAILED) from error
        action = "created" if created else "already protected"
        console.print(f"[green]The VPN server route is {action}.[/green]")
        console.print(
            f"{state.server_ip}/32 via {state.gateway} "
            f"dev {state.interface} src {state.source_ip}"
        )
        console.print(f"Ownership state: {RouteGuardStore().path}")
        console.print("The default route and DNS were unchanged.")
        return
    if not dry_run:
        console.print("[yellow]Choose --dry-run or --apply.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    try:
        baseline = inspect_network_baseline(server_ip)
    except (NetworkInspectionError, ValueError) as error:
        console.print(f"[red]Network inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    console.print(f"[bold]VPN server route guard dry-run for {server_ip}[/bold]")
    for number, step in enumerate(
        build_server_route_guard_plan(baseline),
        start=1,
    ):
        console.print(f"{number}. {step.description}")
        if command := step.rendered_command():
            console.print(f"   [dim]{command}[/dim]")
    console.print("[green]Dry-run completed. No route or DNS setting was changed.[/green]")


@network_app.command("unprotect-server")
def network_unprotect_server(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Remove only the server route owned by this project",
    ),
) -> None:
    """Remove the recorded server route after exact ownership verification."""

    if not apply:
        console.print("[yellow]Pass --apply to remove the owned server route.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    if os.geteuid() != 0:
        console.print(
            "[red]Route cleanup requires root privileges.[/red] Run the installed "
            "virtual-environment command with sudo."
        )
        raise typer.Exit(ExitCode.CHECK_FAILED)
    try:
        state, removed = unprotect_server_route()
    except (OSError, RouteGuardError) as error:
        console.print(f"[red]Route cleanup failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error
    if state is None:
        console.print("[green]No project-owned server route was recorded.[/green]")
    elif removed:
        console.print(
            f"[green]Removed the project-owned route for {state.server_ip}.[/green]"
        )
    else:
        console.print(
            "[green]The recorded route was already absent; stale ownership was cleared.[/green]"
        )


@network_app.command("lease-test")
def network_lease_test(
    server_ip: str = typer.Argument(help="Public IPv4 address of the VPN server"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the isolated DHCP lease test without running it",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Run the temporary address-only DHCP test and clean it up",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        min=10,
        max=120,
        help="Maximum connection and DHCP wait time in seconds",
    ),
) -> None:
    """Plan an address-only DHCP test through the SoftEther tunnel."""

    if dry_run and apply:
        console.print("[red]Choose either --dry-run or --apply, not both.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)
    project_root = Path(__file__).resolve().parents[2]
    if apply:
        if os.geteuid() != 0:
            console.print(
                "[red]The lease test requires root privileges.[/red] Run the "
                "installed virtual-environment command with sudo."
            )
            raise typer.Exit(ExitCode.CHECK_FAILED)
        try:
            result = run_lease_test(
                server_ip,
                timeout_seconds=timeout,
                project_root=project_root,
            )
        except (
            LeaseTestError,
            NetworkInspectionError,
            OSError,
            RouteGuardError,
            subprocess.TimeoutExpired,
            TunnelTestError,
            ValueError,
        ) as error:
            console.print(f"[red]Lease test failed:[/red] {error}")
            raise typer.Exit(ExitCode.NETWORK_ERROR) from error
        console.print("[green]The isolated VPN IPv4 lease test succeeded.[/green]")
        console.print(f"Leased address: {result.address}/{result.prefix_length}")
        console.print(
            "Offered VPN routers: "
            + (", ".join(result.offered_routers) or "None")
        )
        console.print(
            "Offered VPN DNS servers: "
            + (", ".join(result.offered_dns_servers) or "None")
        )
        console.print(f"Tunnel status checks: {result.tunnel_status_checks}")
        console.print("Default route unchanged: yes")
        console.print("Default DNS interface unchanged: yes")
        console.print(
            "[green]The temporary lease, tunnel, and owned server route were cleaned up.[/green]"
        )
        return
    if not dry_run:
        console.print("[yellow]Choose --dry-run or --apply.[/yellow]")
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    try:
        baseline = inspect_network_baseline(server_ip)
    except (NetworkInspectionError, ValueError) as error:
        console.print(f"[red]Network inspection failed:[/red] {error}")
        raise typer.Exit(ExitCode.INSPECTION_FAILED) from error

    console.print(f"[bold]Isolated VPN IPv4 lease test dry-run for {server_ip}[/bold]")
    for number, step in enumerate(
        build_dhcp_test_plan(baseline, project_root=project_root),
        start=1,
    ):
        console.print(f"{number}. {step.description}")
        if command := step.rendered_command():
            console.print(f"   [dim]{command}[/dim]")
    console.print(
        "[green]Dry-run completed. The tunnel, addresses, routes, and DNS were unchanged.[/green]"
    )


@sources_app.command("list")
def sources_list() -> None:
    """List configured sources in the order they will be tried."""

    try:
        custom_sources = SourceStore().custom_sources()
    except ValueError as error:
        console.print(f"[red]Source configuration error:[/red] {error}")
        raise typer.Exit(ExitCode.DATA_ERROR) from error

    store = SourceStore()
    table = Table(title="VPN Gate sources")
    table.add_column("Priority", justify="right")
    table.add_column("Kind")
    table.add_column("URL")
    for priority, source_url in enumerate(store.all_sources(), start=1):
        kind = "custom" if source_url in custom_sources else "default"
        table.add_row(str(priority), kind, source_url)
    console.print(table)


@sources_app.command("add")
def sources_add(
    source_url: str = typer.Argument(help="Mirror base URL or API endpoint"),
    allow_http: bool = typer.Option(
        False,
        "--allow-http",
        help="Allow an unencrypted HTTP mirror source",
    ),
) -> None:
    """Add a persistent mirror source before the default API endpoint."""

    try:
        normalized = SourceStore().add(source_url, allow_http=allow_http)
    except ValueError as error:
        console.print(f"[red]Invalid source:[/red] {error}")
        raise typer.Exit(ExitCode.INVALID_INPUT) from error
    console.print(f"[green]Source is configured:[/green] {normalized}")


@sources_app.command("remove")
def sources_remove(
    source_url: str = typer.Argument(help="Configured mirror base URL or API endpoint"),
) -> None:
    """Remove a persistent custom source without affecting the default source."""

    try:
        removed = SourceStore().remove(source_url)
    except ValueError as error:
        console.print(f"[red]Invalid source:[/red] {error}")
        raise typer.Exit(ExitCode.INVALID_INPUT) from error
    if not removed:
        console.print("[yellow]Source was not configured.[/yellow]")
        raise typer.Exit(ExitCode.DATA_ERROR)
    console.print("[green]Source removed.[/green]")


@servers_app.command("refresh")
def servers_refresh(
    source: str | None = typer.Option(
        None,
        "--source",
        help="Try this source first without saving it",
    ),
    allow_http: bool = typer.Option(
        False,
        "--allow-http",
        help="Allow an unencrypted HTTP source passed with --source",
    ),
) -> None:
    """Fetch the first working source and atomically replace the server cache."""

    try:
        sources = SourceStore().all_sources()
        if source is not None:
            normalized_source = normalize_source_url(source)
            require_http_opt_in(normalized_source, allow_http=allow_http)
            sources.insert(0, normalized_source)
        sources = list(dict.fromkeys(sources))
        cache_store = CacheStore()
        cache = refresh_from_sources(sources, cache_store)
    except ValueError as error:
        console.print(f"[red]Configuration or data error:[/red] {error}")
        raise typer.Exit(ExitCode.DATA_ERROR) from error
    except AllSourcesFailed as error:
        console.print("[red]Every configured VPN Gate source failed.[/red]")
        for failure in error.failures:
            console.print(f"- {failure.source_url}: {failure.detail}")
        raise typer.Exit(ExitCode.NETWORK_ERROR) from error

    console.print(f"[green]Cached {len(cache.servers)} servers.[/green]")
    console.print(f"Source: {cache.source_url}")
    console.print(f"Rejected rows: {cache.rejected_rows}")
    console.print(f"Cache: {cache_store.path}")


@servers_app.command("list")
def servers_list(
    country: str | None = typer.Option(
        None,
        "--country",
        help="Two-letter country code",
    ),
    limit: int = typer.Option(20, min=1, max=200, help="Maximum rows to show"),
) -> None:
    """List cached servers without making a network request."""

    if country is not None and len(country) != 2:
        console.print("[red]Country must be a two-letter code.[/red]")
        raise typer.Exit(ExitCode.INVALID_INPUT)

    try:
        cache = CacheStore().load()
    except (FileNotFoundError, ValueError) as error:
        console.print(f"[red]Cache error:[/red] {error}")
        raise typer.Exit(ExitCode.DATA_ERROR) from error

    servers = cache.servers
    if country is not None:
        country_code = country.upper()
        servers = tuple(
            server for server in servers if server.country_short == country_code
        )
    servers = tuple(sorted(servers, key=lambda item: (-item.score, item.ping_ms)))

    table = Table(title=f"Cached VPN Gate servers ({cache.fetched_at:%Y-%m-%d %H:%M UTC})")
    table.add_column("IP")
    table.add_column("Country")
    table.add_column("Ping", justify="right")
    table.add_column("Speed", justify="right")
    table.add_column("Sessions", justify="right")
    table.add_column("Uptime", justify="right")
    table.add_column("Score", justify="right")
    for server in servers[:limit]:
        table.add_row(
            str(server.ip),
            server.country_short,
            f"{server.ping_ms} ms",
            f"{server.speed_mbps:.1f} Mbps",
            str(server.sessions),
            f"{server.uptime_days:.1f} d",
            str(server.score),
        )
    console.print(table)
    console.print(f"Showing {min(len(servers), limit)} of {len(servers)} matching servers.")
    console.print(f"Source: {cache.source_url}")


@servers_app.command("select")
def servers_select(
    country: str | None = typer.Option(
        None,
        "--country",
        help="Two-letter country code",
    ),
    max_ping: int | None = typer.Option(
        None,
        "--max-ping",
        min=0,
        help="Maximum source-reported ping in milliseconds",
    ),
    min_speed: float = typer.Option(
        0,
        "--min-speed",
        min=0,
        help="Minimum source-reported speed in Mbps",
    ),
    limit: int = typer.Option(5, min=1, max=20, help="Number of candidates"),
) -> None:
    """Recommend cached servers using explicit filters and official scores."""

    try:
        criteria = SelectionCriteria(
            country=country,
            max_ping_ms=max_ping,
            min_speed_mbps=min_speed,
        )
    except ValueError as error:
        console.print(f"[red]Invalid selection criteria:[/red] {error}")
        raise typer.Exit(ExitCode.INVALID_INPUT) from error

    try:
        cache = CacheStore().load()
        selected = select_servers(cache.servers, criteria, limit=limit)
    except (FileNotFoundError, ValueError) as error:
        console.print(f"[red]Selection error:[/red] {error}")
        raise typer.Exit(ExitCode.DATA_ERROR) from error

    if not selected:
        console.print("[yellow]No cached server matches all requested filters.[/yellow]")
        raise typer.Exit(ExitCode.DATA_ERROR)

    table = Table(title="Recommended cached VPN Gate servers")
    table.add_column("Rank", justify="right")
    table.add_column("IP")
    table.add_column("Country")
    table.add_column("Ping", justify="right")
    table.add_column("Speed", justify="right")
    table.add_column("Sessions", justify="right")
    table.add_column("Score", justify="right")
    for rank, server in enumerate(selected, start=1):
        table.add_row(
            str(rank),
            str(server.ip),
            server.country_short,
            f"{server.ping_ms} ms",
            f"{server.speed_mbps:.1f} Mbps",
            str(server.sessions),
            str(server.score),
        )
    console.print(table)
    console.print(
        "[dim]Ping and speed are source-reported estimates, not measurements "
        "from this computer.[/dim]"
    )
    console.print(f"Cache: {cache.fetched_at:%Y-%m-%d %H:%M UTC}")
    if datetime.now(UTC) - cache.fetched_at > timedelta(minutes=30):
        console.print(
            "[yellow]The cache is more than 30 minutes old; refresh it before "
            "attempting a connection.[/yellow]"
        )
    console.print(
        f"Next safe step: uv run vpngate softether prepare {selected[0].ip} --dry-run"
    )


@servers_app.command("import")
def servers_import(
    path: Path = typer.Argument(
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Downloaded VPN Gate CSV file",
    ),
) -> None:
    """Validate a downloaded CSV file and atomically replace the server cache."""

    cache_store = CacheStore()
    try:
        cache = import_server_file(path, cache_store)
    except ValueError as error:
        console.print(f"[red]Import failed:[/red] {error}")
        raise typer.Exit(ExitCode.DATA_ERROR) from error
    console.print(f"[green]Imported {len(cache.servers)} servers.[/green]")
    console.print(f"Rejected rows: {cache.rejected_rows}")
    console.print(f"Cache: {cache_store.path}")


def main() -> None:
    app()
