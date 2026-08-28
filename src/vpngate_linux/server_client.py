from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
from typing import Callable, Iterable

import httpx

from .server_storage import CacheStore
from .servers import ServerCache, make_cache, parse_server_csv


USER_AGENT = "vpngate-linux/1.0 (+https://github.com/aboumelon/vpngate-linux)"
MAX_IMPORT_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class SourceFailure:
    source_url: str
    detail: str


class AllSourcesFailed(RuntimeError):
    def __init__(self, failures: tuple[SourceFailure, ...]) -> None:
        self.failures = failures
        super().__init__("All VPN Gate sources failed")


def fetch_payload(source_url: str) -> str:
    try:
        with httpx.Client(
            timeout=httpx.Timeout(connect=8, read=60, write=10, pool=5),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            response = client.get(source_url)
            response.raise_for_status()
            return response.text
    except (httpx.ReadTimeout, httpx.RemoteProtocolError) as error:
        return _fetch_payload_with_curl(source_url, original_error=error)


def _fetch_payload_with_curl(
    source_url: str,
    *,
    original_error: httpx.HTTPError,
) -> str:
    curl = shutil.which("curl")
    if curl is None:
        raise original_error
    try:
        completed = subprocess.run(
            (
                curl,
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--connect-timeout",
                "8",
                "--max-time",
                "90",
                "--max-filesize",
                str(MAX_IMPORT_BYTES),
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--user-agent",
                USER_AGENT,
                source_url,
            ),
            capture_output=True,
            check=False,
            timeout=95,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OSError(f"curl fallback failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OSError(f"curl fallback failed: {detail or 'unknown error'}")
    try:
        return completed.stdout.decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError(f"curl response is not valid UTF-8: {error}") from error


def refresh_from_sources(
    sources: Iterable[str],
    cache_store: CacheStore,
    fetcher: Callable[[str], str] = fetch_payload,
) -> ServerCache:
    failures = []
    for source_url in sources:
        try:
            result = parse_server_csv(fetcher(source_url))
            cache = make_cache(source_url, result)
            cache_store.save(cache)
            return cache
        except (httpx.HTTPError, OSError, UnicodeError, ValueError) as error:
            failures.append(SourceFailure(source_url, str(error)))
    raise AllSourcesFailed(tuple(failures))


def import_server_file(path: Path, cache_store: CacheStore) -> ServerCache:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"Could not inspect import file: {error}") from error
    if size > MAX_IMPORT_BYTES:
        raise ValueError("Import file is larger than 25 MiB")
    try:
        payload = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Could not read import file: {error}") from error
    result = parse_server_csv(payload)
    cache = make_cache(path.resolve().as_uri(), result)
    cache_store.save(cache)
    return cache
