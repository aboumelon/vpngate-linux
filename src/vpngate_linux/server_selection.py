from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .servers import ServerRecord


@dataclass(frozen=True)
class SelectionCriteria:
    country: str | None = None
    max_ping_ms: int | None = None
    min_speed_mbps: float = 0

    def __post_init__(self) -> None:
        if self.country is not None and len(self.country) != 2:
            raise ValueError("Country must be a two-letter code")
        if self.max_ping_ms is not None and self.max_ping_ms < 0:
            raise ValueError("Maximum ping cannot be negative")
        if self.min_speed_mbps < 0:
            raise ValueError("Minimum speed cannot be negative")


def select_servers(
    servers: Iterable[ServerRecord],
    criteria: SelectionCriteria,
    *,
    limit: int = 5,
) -> tuple[ServerRecord, ...]:
    if limit < 1:
        raise ValueError("Limit must be at least one")

    country = criteria.country.upper() if criteria.country else None
    matching = (
        server
        for server in servers
        if (country is None or server.country_short == country)
        and (criteria.max_ping_ms is None or server.ping_ms <= criteria.max_ping_ms)
        and server.speed_mbps >= criteria.min_speed_mbps
    )
    ranked = sorted(
        matching,
        key=lambda server: (
            -server.score,
            server.ping_ms,
            -server.speed_bps,
            server.sessions,
            int(server.ip),
        ),
    )

    unique = []
    seen_addresses = set()
    for server in ranked:
        if server.ip in seen_addresses:
            continue
        seen_addresses.add(server.ip)
        unique.append(server)
        if len(unique) == limit:
            break
    return tuple(unique)
