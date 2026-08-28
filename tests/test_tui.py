import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static

from vpngate_linux.server_storage import CacheStore
from vpngate_linux.servers import parse_server_csv
from vpngate_linux.tui import VpnGateTui, load_cached_candidates


class TuiTests(unittest.TestCase):
    def test_app_can_be_constructed(self) -> None:
        app = VpnGateTui()
        self.assertEqual(app.TITLE, "vpngate-linux")

    def test_cached_candidates_use_the_country_filter(self) -> None:
        payload = """#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
vpn1,8.8.8.8,100,10,300000000,Japan,JP,2,1000,5,10,2,operator,message,
vpn2,1.1.1.1,200,20,400000000,Australia,AU,3,1000,5,10,2,operator,message,
*
"""
        servers = parse_server_csv(payload).servers
        cache = type("Cache", (), {"servers": servers})()

        with patch.object(CacheStore, "load", return_value=cache):
            selected = load_cached_candidates("jp")

        self.assertEqual(tuple(str(server.ip) for server in selected), ("8.8.8.8",))


class TuiMountTests(unittest.IsolatedAsyncioTestCase):
    async def test_mounted_app_renders_cached_servers(self) -> None:
        payload = """#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
vpn1,8.8.8.8,100,10,300000000,Japan,JP,2,1000,5,10,2,operator,message,
*
"""
        servers = parse_server_csv(payload).servers
        cache = type("Cache", (), {"servers": servers})()
        app = VpnGateTui()

        with patch.object(CacheStore, "load", return_value=cache):
            async with app.run_test(size=(100, 35)):
                table = app.query_one("#servers", DataTable)
                message = app.query_one("#message", Static)

                self.assertEqual(table.row_count, 1)
                self.assertIn("Loaded 1 candidate", str(message.content))


if __name__ == "__main__":
    unittest.main()
