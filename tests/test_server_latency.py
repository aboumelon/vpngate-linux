from pathlib import Path
import unittest
from unittest.mock import patch

from vpngate_linux.server_latency import (
    TcpLatencyResult,
    measure_tcp_latency,
    probe_server_latencies,
)
from vpngate_linux.servers import parse_server_csv


FIXTURE = Path(__file__).parent / "fixtures" / "vpngate.csv"


class ServerLatencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = parse_server_csv(
            FIXTURE.read_text(encoding="utf-8")
        ).servers[0]

    def test_uses_the_median_of_successful_tcp_attempts(self) -> None:
        measurements = iter((31.0, None, 11.0, 21.0))

        result = measure_tcp_latency(
            self.server,
            attempts=4,
            attempt=lambda _host, _port, _timeout: next(measurements),
        )

        self.assertEqual(result.median_ms, 21.0)
        self.assertEqual(result.successful_attempts, 3)
        self.assertEqual(result.attempts, 4)
        self.assertTrue(result.reachable)

    def test_reports_an_unreachable_server_without_a_fake_latency(self) -> None:
        result = measure_tcp_latency(
            self.server,
            attempts=3,
            attempt=lambda _host, _port, _timeout: None,
        )

        self.assertIsNone(result.median_ms)
        self.assertEqual(result.successful_attempts, 0)
        self.assertFalse(result.reachable)

    def test_rejects_invalid_probe_settings(self) -> None:
        with self.assertRaisesRegex(ValueError, "Attempts"):
            measure_tcp_latency(self.server, attempts=0)
        with self.assertRaisesRegex(ValueError, "Timeout"):
            measure_tcp_latency(self.server, timeout=0)
        with self.assertRaisesRegex(ValueError, "Port"):
            measure_tcp_latency(self.server, port=0)

    def test_ranks_reachable_servers_by_local_median(self) -> None:
        servers = parse_server_csv(
            FIXTURE.read_text(encoding="utf-8")
        ).servers
        latencies = {
            str(servers[0].ip): None,
            str(servers[1].ip): 42.5,
        }

        def fake_measure(server, **_kwargs):
            latency = latencies[str(server.ip)]
            return TcpLatencyResult(
                server=server,
                median_ms=latency,
                successful_attempts=3 if latency is not None else 0,
                attempts=3,
            )

        with patch(
            "vpngate_linux.server_latency.measure_tcp_latency",
            side_effect=fake_measure,
        ):
            results = probe_server_latencies(servers, workers=2)

        self.assertEqual(results[0].server, servers[1])
        self.assertTrue(results[0].reachable)
        self.assertFalse(results[1].reachable)


if __name__ == "__main__":
    unittest.main()
