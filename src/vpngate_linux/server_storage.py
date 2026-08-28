from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import tempfile
from urllib.parse import urlsplit, urlunsplit

from platformdirs import user_cache_path, user_config_path
from pydantic import ValidationError

from .servers import ServerCache


DEFAULT_SOURCE_URL = "https://www.vpngate.net/api/iphone/"


def default_cache_path() -> Path:
    """Return the cache path for the user who launched the command.

    The TUI runs as root because connection management changes system networking.
    Under sudo, platformdirs would otherwise resolve the cache below root's home
    even though the server refresh was run by the desktop user.
    """

    if os.geteuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        if sudo_uid:
            try:
                invoking_user = pwd.getpwuid(int(sudo_uid))
            except (KeyError, ValueError):
                pass
            else:
                return (
                    Path(invoking_user.pw_dir)
                    / ".cache"
                    / "vpngate-linux"
                    / "servers.json"
                )
    return user_cache_path("vpngate-linux") / "servers.json"


def normalize_source_url(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Source URL must use HTTP or HTTPS and include a host")
    if parsed.username or parsed.password:
        raise ValueError("Source URL must not contain credentials")

    path = parsed.path or "/"
    normalized_path = path
    if path.rstrip("/") in {"", "/en"}:
        normalized_path = "/api/iphone/"
    elif path.rstrip("/") == "/api/iphone":
        normalized_path = "/api/iphone/"

    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, normalized_path, parsed.query, "")
    )


def require_http_opt_in(source: str, *, allow_http: bool) -> None:
    if urlsplit(source).scheme == "http" and not allow_http:
        raise ValueError("HTTP sources require --allow-http")


def _atomic_json_write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


class SourceStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_config_path("vpngate-linux") / "sources.json"

    def custom_sources(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Could not read source configuration: {error}") from error
        sources = data.get("sources")
        if not isinstance(sources, list) or not all(
            isinstance(source, str) for source in sources
        ):
            raise ValueError("Source configuration has an invalid schema")
        return sources

    def all_sources(self) -> list[str]:
        return list(dict.fromkeys((*self.custom_sources(), DEFAULT_SOURCE_URL)))

    def add(self, value: str, *, allow_http: bool = False) -> str:
        source = normalize_source_url(value)
        require_http_opt_in(source, allow_http=allow_http)
        sources = self.custom_sources()
        if source not in sources and source != DEFAULT_SOURCE_URL:
            sources.append(source)
            _atomic_json_write(self.path, {"sources": sources})
        return source

    def remove(self, value: str) -> bool:
        source = normalize_source_url(value)
        sources = self.custom_sources()
        if source not in sources:
            return False
        sources.remove(source)
        _atomic_json_write(self.path, {"sources": sources})
        return True


class CacheStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_cache_path()

    def save(self, cache: ServerCache) -> None:
        _atomic_json_write(self.path, cache.model_dump(mode="json"))

    def load(self) -> ServerCache:
        if not self.path.exists():
            raise FileNotFoundError("Server cache does not exist; run servers refresh")
        try:
            return ServerCache.model_validate_json(self.path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as error:
            raise ValueError(f"Could not read server cache: {error}") from error
