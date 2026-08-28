from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from statistics import median
import socket
from time import perf_counter
from typing import Callable, Iterable

from .servers import ServerRecord


TcpAttempt = Callable[[str, int, float], float | None]


@dataclass(frozen=True)
class TcpLatencyResult:
    server: ServerRecord
    median_ms: float | None
    successful_attempts: int
    attempts: int

    @property
    def reachable(self) -> bool:
        return self.median_ms is not None


def _tcp_attempt(host: str, port: int, timeout: float) -> float | None:
    started = perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return None
    return (perf_counter() - started) * 1_000


def measure_tcp_latency(
    server: ServerRecord,
    *,
    port: int = 443,
    attempts: int = 3,
    timeout: float = 1.5,
    attempt: TcpAttempt = _tcp_attempt,
) -> TcpLatencyResult:
    if not 1 <= port <= 65_535:
        raise ValueError("Port must be between 1 and 65535")
    if attempts < 1:
        raise ValueError("Attempts must be at least one")
    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    measurements = []
    for _ in range(attempts):
        elapsed_ms = attempt(str(server.ip), port, timeout)
        if elapsed_ms is not None:
            measurements.append(elapsed_ms)

    return TcpLatencyResult(
        server=server,
        median_ms=median(measurements) if measurements else None,
        successful_attempts=len(measurements),
        attempts=attempts,
    )


def probe_server_latencies(
    servers: Iterable[ServerRecord],
    *,
    port: int = 443,
    attempts: int = 3,
    timeout: float = 1.5,
    workers: int = 10,
) -> tuple[TcpLatencyResult, ...]:
    candidates = tuple(servers)
    if workers < 1:
        raise ValueError("Workers must be at least one")
    if not candidates:
        return ()

    def measure(server: ServerRecord) -> TcpLatencyResult:
        return measure_tcp_latency(
            server,
            port=port,
            attempts=attempts,
            timeout=timeout,
        )

    with ThreadPoolExecutor(max_workers=min(workers, len(candidates))) as executor:
        results = tuple(executor.map(measure, candidates))

    return tuple(
        sorted(
            results,
            key=lambda result: (
                not result.reachable,
                result.median_ms if result.median_ms is not None else float("inf"),
                -result.server.score,
                int(result.server.ip),
            ),
        )
    )
