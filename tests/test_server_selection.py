from pathlib import Path
import unittest

from vpngate_linux.server_selection import SelectionCriteria, select_servers
from vpngate_linux.servers import parse_server_csv


FIXTURE = Path(__file__).parent / "fixtures" / "vpngate.csv"


class ServerSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.servers = parse_server_csv(
            FIXTURE.read_text(encoding="utf-8")
        ).servers

    def test_ranks_matching_servers_by_official_score(self) -> None:
        selected = select_servers(self.servers, SelectionCriteria(), limit=2)

        self.assertEqual(len(selected), 2)
        self.assertGreaterEqual(selected[0].score, selected[1].score)

    def test_filters_country_ping_and_speed(self) -> None:
        selected = select_servers(
            self.servers,
            SelectionCriteria(country="jp", max_ping_ms=20, min_speed_mbps=300),
        )

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].country_short, "JP")

    def test_returns_empty_result_when_nothing_matches(self) -> None:
        selected = select_servers(
            self.servers,
            SelectionCriteria(country="DE"),
        )

        self.assertEqual(selected, ())

    def test_rejects_invalid_criteria(self) -> None:
        with self.assertRaisesRegex(ValueError, "two-letter"):
            SelectionCriteria(country="Japan")
        with self.assertRaisesRegex(ValueError, "negative"):
            SelectionCriteria(max_ping_ms=-1)
        with self.assertRaisesRegex(ValueError, "negative"):
            SelectionCriteria(min_speed_mbps=-1)


if __name__ == "__main__":
    unittest.main()
