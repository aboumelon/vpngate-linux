from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx

from vpngate_linux.server_client import (
    AllSourcesFailed,
    MAX_IMPORT_BYTES,
    _fetch_payload_with_curl,
    import_server_file,
    refresh_from_sources,
)
from vpngate_linux.server_storage import (
    CacheStore,
    DEFAULT_SOURCE_URL,
    SourceStore,
    default_cache_path,
    normalize_source_url,
    require_http_opt_in,
)
from vpngate_linux.servers import parse_server_csv


FIXTURE = Path(__file__).parent / "fixtures" / "vpngate.csv"


class ServerParserTests(unittest.TestCase):
    def test_parses_valid_rows_and_rejects_invalid_rows(self) -> None:
        result = parse_server_csv(FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(len(result.servers), 2)
        self.assertEqual(result.rejected_rows, 1)
        self.assertEqual(result.servers[0].country_short, "JP")
        self.assertAlmostEqual(result.servers[0].speed_mbps, 324.481507)

    def test_preserves_quoted_commas(self) -> None:
        result = parse_server_csv(FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(result.servers[1].operator, "Example, Inc.")

    def test_rejects_missing_header(self) -> None:
        with self.assertRaisesRegex(ValueError, "header was not found"):
            parse_server_csv("not a VPN Gate response")


class SourceStoreTests(unittest.TestCase):
    def test_normalizes_primary_and_mirror_page_urls(self) -> None:
        self.assertEqual(
            normalize_source_url("https://www.vpngate.net"),
            DEFAULT_SOURCE_URL,
        )
        self.assertEqual(
            normalize_source_url("http://203.0.113.10:1234/en/"),
            "http://203.0.113.10:1234/api/iphone/",
        )

    def test_http_requires_explicit_permission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(Path(directory) / "sources.json")

            with self.assertRaisesRegex(ValueError, "--allow-http"):
                store.add("http://203.0.113.10:1234/en/")

    def test_temporary_http_source_requires_explicit_permission(self) -> None:
        source = normalize_source_url("http://203.0.113.10:1234/en/")

        with self.assertRaisesRegex(ValueError, "--allow-http"):
            require_http_opt_in(source, allow_http=False)
        require_http_opt_in(source, allow_http=True)

    def test_custom_sources_are_tried_before_the_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(Path(directory) / "sources.json")
            mirror = store.add("https://mirror.example/en/")

            self.assertEqual(store.all_sources(), [mirror, DEFAULT_SOURCE_URL])

    def test_custom_source_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(Path(directory) / "sources.json")
            mirror = store.add("https://mirror.example/en/")

            self.assertTrue(store.remove(mirror))
            self.assertFalse(store.remove(mirror))
            self.assertEqual(store.all_sources(), [DEFAULT_SOURCE_URL])


class CacheAndRefreshTests(unittest.TestCase):
    def test_default_cache_uses_the_invoking_user_under_sudo(self) -> None:
        invoking_user = SimpleNamespace(pw_dir="/home/example")

        with (
            patch("vpngate_linux.server_storage.os.geteuid", return_value=0),
            patch.dict("os.environ", {"SUDO_UID": "1000"}, clear=True),
            patch(
                "vpngate_linux.server_storage.pwd.getpwuid",
                return_value=invoking_user,
            ) as getpwuid,
        ):
            path = default_cache_path()

        self.assertEqual(
            path,
            Path("/home/example/.cache/vpngate-linux/servers.json"),
        )
        getpwuid.assert_called_once_with(1000)

    def test_default_cache_falls_back_for_an_invalid_sudo_uid(self) -> None:
        expected = Path("/tmp/example-cache/vpngate-linux/servers.json")

        with (
            patch("vpngate_linux.server_storage.os.geteuid", return_value=0),
            patch.dict("os.environ", {"SUDO_UID": "invalid"}, clear=True),
            patch(
                "vpngate_linux.server_storage.user_cache_path",
                return_value=expected.parent,
            ),
        ):
            path = default_cache_path()

        self.assertEqual(path, expected)

    def test_import_size_limit_is_bounded(self) -> None:
        self.assertEqual(MAX_IMPORT_BYTES, 25 * 1024 * 1024)

    @patch("vpngate_linux.server_client.shutil.which", return_value="/usr/bin/curl")
    @patch("vpngate_linux.server_client.subprocess.run")
    def test_curl_fallback_does_not_use_a_shell(self, run, _which) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=FIXTURE.read_bytes(),
            stderr=b"",
        )
        original_error = httpx.ReadTimeout("slow mirror")

        payload = _fetch_payload_with_curl(
            "http://mirror.example/api/iphone/",
            original_error=original_error,
        )

        self.assertIn("*vpn_servers", payload)
        called_args = run.call_args.args[0]
        self.assertIsInstance(called_args, tuple)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("--max-filesize", called_args)
        self.assertIn("=http,https", called_args)

    def test_cache_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_store = CacheStore(Path(directory) / "servers.json")
            refresh_from_sources(
                (DEFAULT_SOURCE_URL,),
                cache_store,
                lambda _: FIXTURE.read_text(encoding="utf-8"),
            )

            loaded = cache_store.load()
            self.assertEqual(len(loaded.servers), 2)
            self.assertEqual(loaded.rejected_rows, 1)

    def test_imported_file_becomes_the_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_store = CacheStore(Path(directory) / "servers.json")

            imported = import_server_file(FIXTURE, cache_store)

            self.assertEqual(len(imported.servers), 2)
            self.assertTrue(imported.source_url.startswith("file://"))
            self.assertEqual(cache_store.load(), imported)

    def test_refresh_falls_back_to_the_next_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_store = CacheStore(Path(directory) / "servers.json")

            def fetcher(source: str) -> str:
                if source == "https://broken.example/api/iphone/":
                    raise OSError("offline")
                return FIXTURE.read_text(encoding="utf-8")

            cache = refresh_from_sources(
                ("https://broken.example/api/iphone/", DEFAULT_SOURCE_URL),
                cache_store,
                fetcher,
            )

            self.assertEqual(cache.source_url, DEFAULT_SOURCE_URL)

    def test_all_source_failures_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_store = CacheStore(Path(directory) / "servers.json")

            with self.assertRaises(AllSourcesFailed) as raised:
                refresh_from_sources(
                    ("https://one.example/", "https://two.example/"),
                    cache_store,
                    lambda source: (_ for _ in ()).throw(OSError(source)),
                )

            self.assertEqual(len(raised.exception.failures), 2)


if __name__ == "__main__":
    unittest.main()
