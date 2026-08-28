from __future__ import annotations

import os
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from .connection_session import (
    ConnectionSessionError,
    connect_vpn,
    disconnect_vpn,
    inspect_connection_status,
)
from .server_selection import SelectionCriteria, select_servers
from .server_storage import CacheStore
from .servers import ServerRecord


def load_cached_candidates(
    country: str | None = None,
    *,
    limit: int = 20,
) -> tuple[ServerRecord, ...]:
    normalized_country = country.strip().upper() if country else None
    criteria = SelectionCriteria(country=normalized_country or None)
    cache = CacheStore().load()
    return select_servers(cache.servers, criteria, limit=limit)


class VpnGateTui(App[None]):
    TITLE = "vpngate-linux"
    SUB_TITLE = "Safe VPN Gate connection manager"

    CSS = """
    Screen {
        layout: vertical;
    }
    #controls {
        height: auto;
        padding: 1;
    }
    #country {
        width: 20;
        margin-right: 1;
    }
    Button {
        margin-right: 1;
    }
    #servers {
        height: 1fr;
    }
    #message {
        height: auto;
        min-height: 4;
        padding: 1;
        border-top: solid $accent;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("l", "load_servers", "Load servers"),
        ("s", "show_status", "Status"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.candidates: tuple[ServerRecord, ...] = ()

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Input(placeholder="Country code, e.g. JP", id="country")
            yield Button("Load cached servers", id="load", variant="primary")
            yield Button("Connect selected", id="connect", variant="success")
            yield Button("Disconnect", id="disconnect", variant="warning")
            yield Button("Status", id="status")
        yield DataTable(id="servers", cursor_type="row", zebra_stripes=True)
        yield Static("Load the cache, select a server, then connect.", id="message")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#servers", DataTable)
        table.add_columns("Rank", "IP", "Country", "Ping", "Speed", "Sessions")
        self.action_load_servers()

    def _message(self, text: str) -> None:
        self.query_one("#message", Static).update(text)

    def _selected_server(self) -> ServerRecord | None:
        table = self.query_one("#servers", DataTable)
        if not self.candidates or table.cursor_row >= len(self.candidates):
            return None
        return self.candidates[table.cursor_row]

    def action_load_servers(self) -> None:
        country = self.query_one("#country", Input).value
        try:
            candidates = load_cached_candidates(country)
        except (FileNotFoundError, ValueError) as error:
            self._message(f"Could not load cached servers: {error}")
            return
        self.candidates = candidates
        table = self.query_one("#servers", DataTable)
        table.clear()
        for rank, server in enumerate(candidates, start=1):
            table.add_row(
                str(rank),
                str(server.ip),
                server.country_short,
                f"{server.ping_ms} ms",
                f"{server.speed_mbps:.1f} Mbps",
                str(server.sessions),
            )
        if candidates:
            self._message(
                f"Loaded {len(candidates)} candidates. Select one and connect."
            )
        else:
            self._message("No cached server matches this country filter.")

    def action_show_status(self) -> None:
        self.show_status_worker()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load":
            self.action_load_servers()
        elif event.button.id == "connect":
            server = self._selected_server()
            if server is None:
                self._message("Select a cached server first.")
            elif os.geteuid() != 0:
                self._message("Restart the TUI with sudo to connect.")
            else:
                self.connect_worker(str(server.ip))
        elif event.button.id == "disconnect":
            if os.geteuid() != 0:
                self._message("Restart the TUI with sudo to disconnect.")
            else:
                self.disconnect_worker()
        elif event.button.id == "status":
            self.action_show_status()

    @work(thread=True, exclusive=True, group="vpn-operation")
    def connect_worker(self, server_ip: str) -> None:
        self.call_from_thread(self._message, f"Connecting to {server_ip}...")
        try:
            result = connect_vpn(
                server_ip,
                project_root=Path(__file__).resolve().parents[2],
            )
        except Exception as error:
            self.call_from_thread(self._message, f"Connection failed: {error}")
            return
        public_ip = result.public_ip or "unavailable"
        self.call_from_thread(
            self._message,
            f"Connected to {result.server_ip}\n"
            f"VPN address: {result.vpn_address}\n"
            f"Public IPv4: {public_ip}",
        )

    @work(thread=True, exclusive=True, group="vpn-operation")
    def disconnect_worker(self) -> None:
        self.call_from_thread(self._message, "Disconnecting...")
        try:
            result = disconnect_vpn()
        except Exception as error:
            self.call_from_thread(self._message, f"Disconnection failed: {error}")
            return
        message = (
            "The managed VPN was disconnected safely."
            if result.had_state
            else "No managed VPN connection was recorded."
        )
        self.call_from_thread(self._message, message)

    @work(thread=True, exclusive=True, group="status-operation")
    def show_status_worker(self) -> None:
        try:
            status = inspect_connection_status()
        except (ConnectionSessionError, OSError) as error:
            self.call_from_thread(self._message, f"Status failed: {error}")
            return
        phase = status.state.phase if status.state is not None else "not recorded"
        self.call_from_thread(
            self._message,
            f"Phase: {phase}\n"
            f"Tunnel: {'connected' if status.tunnel_connected else 'disconnected'}\n"
            f"IPv4 routes: {'active' if status.ipv4_routes_active else 'inactive'}\n"
            f"VPN DNS: {'active' if status.dns_active else 'inactive'}\n"
            f"IPv6 block: {'active' if status.ipv6_block_active else 'inactive'}\n"
            f"Project DHCP processes: {status.project_dhclient_processes}",
        )


def run_tui() -> None:
    VpnGateTui().run()
